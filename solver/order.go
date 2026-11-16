package solver

import (
	"context"
	"fmt"
	"github.com/hlandau/acmetool/responder"
	"github.com/hlandau/acmetool/util"
	denet "github.com/hlandau/goutils/net"
	"github.com/hlandau/xlog"
	"gopkg.in/hlandau/acmeapi.v2"
	"sync"
	"time"
)

var log, Log = xlog.New("acmetool.solver")

// challengeFailures records challenges which have failed during an ordering
// process, so that unsuitable challenges can be avoided where appropriate.
//
// Failures are recorded at one of two scopes, according to whether the error
// which caused the failure is retryable or fatal:
//
//   - Retryable failures are scoped to the individual authorization in which
//     they occurred (and thereby to the current order, since an authorization
//     belongs to exactly one order). They suppress the failed challenge only
//     within that authorization: other authorizations in the same order —
//     even for the same hostname — are unaffected, and if the order has to be
//     rebuilt, the challenges of the new order's authorizations are
//     re-evaluated from scratch, since a retryable failure (e.g. a transient
//     network or hook error) may not recur.
//
//   - Fatal failures are scoped to a hostname for the duration of the
//     ordering process. A fatal failure means the challenge cannot succeed
//     for the hostname no matter how many times the order is rebuilt (e.g.
//     no responder is configured for the challenge type, or the server
//     definitively rejected the challenge), so the challenge is suppressed
//     for all authorizations for that hostname in the current order and any
//     rebuilt orders. This also guarantees the ordering process terminates.
type challengeFailures struct {
	mutex     sync.Mutex
	retryable map[string]struct{}
	fatal     map[string]struct{}
}

func newChallengeFailures() *challengeFailures {
	return &challengeFailures{
		retryable: map[string]struct{}{},
		fatal:     map[string]struct{}{},
	}
}

func retryableFailureKey(authzURL, challengeType string) string {
	return challengeType + "\n" + authzURL
}

func fatalFailureKey(hostname, challengeType string) string {
	return challengeType + "\n" + hostname
}

// Determines whether the given challenge should be avoided for the given
// authorization, either because it failed retryably in this authorization or
// because it failed fatally for this authorization's hostname.
func (cf *challengeFailures) Check(authz *acmeapi.Authorization, challengeType string) bool {
	cf.mutex.Lock()
	defer cf.mutex.Unlock()

	_, ok := cf.retryable[retryableFailureKey(authz.URL, challengeType)]
	if ok {
		return true
	}

	_, ok = cf.fatal[fatalFailureKey(authz.Identifier.Value, challengeType)]
	return ok
}

// Records a retryable failure of the given challenge in the given
// authorization. The failure is forgotten as soon as the order is rebuilt.
func (cf *challengeFailures) AddRetryable(authz *acmeapi.Authorization, challengeType string) {
	cf.mutex.Lock()
	defer cf.mutex.Unlock()

	cf.retryable[retryableFailureKey(authz.URL, challengeType)] = struct{}{}
}

// Records a fatal failure of the given challenge type for the given hostname.
// The failure persists for the duration of the ordering process, including
// across order rebuilds.
func (cf *challengeFailures) AddFatal(hostname, challengeType string) {
	cf.mutex.Lock()
	defer cf.mutex.Unlock()

	cf.fatal[fatalFailureKey(hostname, challengeType)] = struct{}{}
}

// Creates, fulfils and finalises an order. Automatically tries different
// challenges to the extent possible, and creates orders again if necessary
// after challenge failure, until success or unrecoverable failure.
func Order(ctx context.Context, rc *acmeapi.RealmClient, acct *acmeapi.Account, orderTemplate *acmeapi.Order, csr []byte, ccfg *responder.ChallengeConfig) (*acmeapi.Order, error) {

	// Make order.
	// Progress the order. => result: Success | Retry | Fail

	// Fulfil authorizations.
	//   Fulfil challenges by preference/previously failed info; keep prev. failed per (authorization, challenge type)
	//   Retry stuff
	//   Start again if authorization becomes permanently failed
	//   Have faith
	// Finalise

	cf := newChallengeFailures()

	for {
		order := *orderTemplate

		err := rc.NewOrder(ctx, acct, &order)
		if err != nil {
			return nil, err
		}

		shouldRetry, err := orderProcess(ctx, rc, acct, &order, csr, ccfg, cf)
		if err == nil {
			return &order, nil
		}
		if !shouldRetry {
			return nil, err
		}
	}
}

// Take a newly created order object as far as possible.
//
// Returns in one of three states:
//   - Success:                       err == nil  -- OK
//       We're done.
//   - Fail:    shouldRetry == true,  err != nil  -- Order failed but keep making new orders
//       Causes a new order to be made to start the process again.
//   - Fatal:   shouldRetry == false, err != nil	-- Order failed and we will never succeed, so stop
//       Stops the order process.
func orderProcess(ctx context.Context, rc *acmeapi.RealmClient, acct *acmeapi.Account, order *acmeapi.Order, csr []byte, ccfg *responder.ChallengeConfig, cf *challengeFailures) (shouldRetry bool, err error) {
	// We just created the order, so it shouldn't be invalid. If it is, there's
	// no way we can get anywhere no matter how many times we try..
	switch order.Status {
	case acmeapi.OrderPending:
	case acmeapi.OrderReady:
		break
	default:
		return false, fmt.Errorf("order (%q) was in state %q as soon as it was created, cannot continue", order.URL, order.Status)
	}

	if order.Status == acmeapi.OrderPending {
		shouldRetry, err := orderAuthorizeAll(ctx, rc, acct, order, ccfg, cf)
		if err != nil {
			return shouldRetry, err
		}

		// Get a fresh picture of the order status. orderAuthorizeAll doesn't refresh it.
		err = rc.LoadOrder(ctx, acct, order)
		if err != nil {
			return true, err
		}
	}

	// TODO: REMOVE LET'S ENCRYPT WORKAROUND once they fix this
	allowBoulderBugfix := true

	if order.Status != acmeapi.OrderReady && (!allowBoulderBugfix || order.Status != acmeapi.OrderPending) {
		return false, fmt.Errorf("finished authorizing order (%q) but status is not ready, got %q", order.URL, order.Status)
	}

	// Request issuance.
	err = rc.Finalize(ctx, acct, order, csr)
	if err != nil {
		// If finalization failed, this suggests something wrong with the CSR and retrying will be
		// pointless, so stop here.
		return false, err
	}

	return false, nil
}

// Tries to complete all the authorizations on an order.
//
// Returns in one of three states:
//   - Success:                        err == nil  -- OK
//       We're done
//   - Fail:     shouldRetry == true,  err != nil  -- One or more authorizations are dead, but subsequent orders might succeed
//       Cause a new order to be made to start the process again.
//   - Fatal:    shouldRetry == false, err != nil  -- One or more authorizations are unfulfillable and subsequent orders will never succeed
//       Stops the order process.
func orderAuthorizeAll(ctx context.Context, rc *acmeapi.RealmClient, acct *acmeapi.Account, order *acmeapi.Order, ccfg *responder.ChallengeConfig, cf *challengeFailures) (shouldRetry bool, err error) {
	type result struct {
		isFatal bool
		err     error
	}

	ch := make(chan result, len(order.AuthorizationURLs))

	for i := range order.AuthorizationURLs {
		authURL := order.AuthorizationURLs[i]
		go func() {
			ctxAuth := ctx // TODO
			isFatal, err := orderAuthorizeOne(ctxAuth, rc, acct, authURL, ccfg, cf)
			ch <- result{isFatal, err}
		}()
	}

	var errors util.MultiError
	isFatal := false
	for i := 0; i < len(order.AuthorizationURLs); i++ {
		r := <-ch
		if r.isFatal {
			// CANCEL ALL
			isFatal = true
		}

		if r.err != nil {
			errors = append(errors, r.err)
		}
	}

	if len(errors) > 0 {
		return !isFatal, errors
	}

	return true, nil
}

// Tries to complete one authorization given the URL to it. Tries challenges in
// sequence until the authorization becomes invalid or it is determined that
// none of the challenges will work. Avoids challenges which have already
// failed and records challenges which fail, scoped according to whether the
// failure is retryable (to this authorization only) or fatal (to this
// hostname for the remainder of the ordering process).
//
// Returns in one of three states:
//   - Success:                           err == nil  -- OK
//       We're done, authorization is now good
//   - Fail:            isFatal == false, err != nil  -- Authorization is unfulfillable but subsequent orders might succeed
//       Cause a new order to be made to start the process again. Challenge
//       failure records mean a different strategy to complete the
//       authorization may be attempted next time.
//   - Fatal:           isFatal == true,  err != nil  -- Authorization is unfulfillable and subsequent orders will never succeed
//       Authorization process failed and it has been determined that no
//       corresponding successor authorization in a subsequent order could ever
//       succeed either. Give up.
func orderAuthorizeOne(ctx context.Context, rc *acmeapi.RealmClient, acct *acmeapi.Account, authURL string, ccfg *responder.ChallengeConfig, cf *challengeFailures) (isFatal bool, err error) {
	authz := &acmeapi.Authorization{
		URL: authURL,
	}

	// Load authorization.
	err = rc.LoadAuthorization(ctx, acct, authz)
	if err != nil {
		// Assume a transient problem, return FAIL. If there is e.g. a network
		// issue, creation of a new order will fail and that will be fatal, so not
		// checking for fatal errors here is of little consequence.
		return
	}

	// If an authorization was invalid at the outset, consider this a fatal
	// error, otherwise we will just retry with new orders forever but never be
	// able to make any progress. We can only get here if the order is not
	// invalid, so this should only happen if the server creates new orders with
	// a non-final order status but an invalid authorization, which shouldn't
	// happen. Guard against it just in case.
	if authz.Status == acmeapi.AuthorizationInvalid {
		// Return FATAL.
		isFatal = true
		err = fmt.Errorf("authorization %q is invalid from the outset, even though order isn't", authz.URL)
		return
	}

	var challengeErrors util.MultiError
	outOfChallenges := false
	for {
		// If authorization has come to have a final state, return.
		//
		// This will occur either because
		//   - this function has now successfully completed the authorization, or
		//   - because the authorization was created in a final state (e.g. valid)
		//     as soon as the order was created; this can happen if the server
		//     carries over previous successful authorizations, etc.
		// This also handles cases where an authorization randomly transitions to
		// valid, though these aren't expected.
		if authz.Status.IsFinal() {
			if authz.Status == acmeapi.AuthorizationValid {
				// Return SUCCESS.
				return
			}

			// Authorization is dead and cannot be recovered. Return FAIL,
			// creating a new order and starting the process again.
			isFatal = outOfChallenges
			err = util.NewWrapError(challengeErrors, "authorization %q has non-valid final status %q", authz.URL, authz.Status)
			return
		}

		// If any challenge is valid, WTF? Return FATAL.
		for i := range authz.Challenges {
			if authz.Challenges[i].Status == acmeapi.ChallengeValid {
				err = fmt.Errorf("authorization %q has non-final status but contains a valid challenge: %q", authz.URL, authz.Status)
				isFatal = true
				return
			}
		}

		// If the authorization is not for a DNS identifier, return FATAL.
		if authz.Identifier.Type != acmeapi.IdentifierTypeDNS {
			err = fmt.Errorf("unsupported authorization identifier type %q, value %q", authz.Identifier.Type, authz.Identifier.Value)
			isFatal = true
			return
		}

		// Sort challenges by preference.
		preferenceOrder := SortChallenges(authz, PreferFast)

		// Initiate most preferred non-invalid challenge.
		preferred := ""
		secondBestPreferred := ""
		for _, i := range preferenceOrder {
			ch := &authz.Challenges[i]
			if !cf.Check(authz, ch.Type) && !ch.Status.IsFinal() {
				if preferred == "" {
					preferred = ch.URL
				} else if secondBestPreferred == "" {
					secondBestPreferred = ch.URL
				} else {
					break
				}
			}
		}

		// If we've exhausted all challenges, return FATAL.
		if preferred == "" {
			err = util.NewWrapError(challengeErrors, "exhausted all possible challenges in authorization %q", authz.URL)
			isFatal = true
			return
		}

		// Try and complete our preferred challenge. If it fails, record the
		// failure.
		// orderCompleteChallenge returns once the challenge has succeeded, or once
		// it has been determined that it definitely cannot be completed, or once a
		// reasonable effort has been made (e.g. retry limit reached) without
		// success. In failure cases (err != nil), the authorization may or may not
		// have entered a final-invalid state as a result of this, so don't assume
		// the authorization has become final-invalid.
		ch, ok := findChallengeByURL(authz, preferred)
		if !ok {
			panic("challenge disappeared")
		}

		var authWasLoaded bool
		var failureIsFatal bool
		authWasLoaded, failureIsFatal, err = orderCompleteChallenge(ctx, rc, acct, authz, ch.URL, ccfg)
		if err != nil {
			// This challenge failed, so record the failure so we don't try it
			// again where it cannot succeed. Retryable failures are remembered
			// only for this authorization, so the challenge is re-evaluated if
			// the order is rebuilt; fatal failures are remembered for the
			// hostname for the duration of this ordering process.
			if failureIsFatal {
				cf.AddFatal(authz.Identifier.Value, ch.Type)
			} else {
				cf.AddRetryable(authz, ch.Type)
			}

			// As an optimisation, return FATAL instead of FAIL if the challenge we
			// just recorded was the final untried challenge. This is an
			// optimization; if we don't do this, we'll create another order and call
			// this function, orderAuthorizeOne, again before bailing at "exhausted
			// all possible challenges" above. We can avoid this unnecessary creation
			// of an unused order by checking if this is the last untried
			// challenge we're recording a failure for.
			outOfChallenges = (secondBestPreferred == "")

			// Record the error.
			challengeErrors = append(challengeErrors, err)
		}

		// Whether or not orderCompleteChallenge thinks the challenge apparently
		// failed or not, just reload the authorization to check its current state
		// and take that as the actual source of truth (unless
		// orderCompleteChallenge just loaded it). This should be the most reliable
		// strategy. We check whether the authorization has gone final when we
		// continue the loop.
		if !authWasLoaded {
			err = rc.LoadAuthorization(ctx, acct, authz)
			if err != nil {
				return
			}
		}
	}
}

// Tries to complete a single challenge. Returns after it has been completed,
// after it has been determined that it can no longer be completed, or after a
// reasonable effort has been made to complete it.
//
// (If the server implements some manner of evergreen challenge which never
// goes invalid, we don't want to retry forever as the means of completing the
// challenge may not be setup, so we only try once. Retries after spurious
// errors can be handled by the higher levels which invoke this, e.g. at the
// next invocation of acmetool — we probably can't reliably ascertain whether
// an error is spurious ourselves, so we just try once and assume that retries
// will be handled by our invoker.)
//
// Returns in one of two states:
//   - Success:      err == nil  -- OK
//       Challenge was successfully completed; authorization should now be
//       final-valid.
//   - Fail:         err != nil  -- Challenge was attempted one time and failed, authorization MAY OR MAY NOT be final-invalid
//       Challenge was not successfully completed. This may or may not have
//       caused the authorization to transition to final-invalid; for example,
//       some challenges may fail before making any request to the ACME server
//       at all, for example if they detect that they have not been configured
//       (e.g. DNS challenges without any DNS hooks installed). By not assuming
//       the authorization has become invalid we can avoid creating unnecessary
//       orders.
//
// As an optimization, we return whether we reloaded the authorization after
// any possible status changes, which means the caller doesn't need to reload
// it again.
//
// In failure cases, we also return whether the failure is fatal for the
// (hostname, challenge type) pair. A fatal failure is one which demonstrates
// that the challenge cannot possibly be completed for the hostname no matter
// how many times the order is rebuilt — for example, no responder could be
// instantiated for the challenge type, or the server rejected the challenge
// into a final non-valid status. All other failures (e.g. hook errors,
// self-test errors, network errors talking to the ACME server, or non-final
// server-side errors) are considered retryable: they may not recur, so the
// challenge is avoided only within the current authorization and is
// re-evaluated if the order is rebuilt.
func orderCompleteChallenge(ctx context.Context, rc *acmeapi.RealmClient, acct *acmeapi.Account, authz *acmeapi.Authorization, challengeURL string, ccfg *responder.ChallengeConfig) (authWasLoaded, failureIsFatal bool, err error) {
	oldCh, ok := findChallengeByURL(authz, challengeURL)
	if !ok {
		err = fmt.Errorf("challenge %q does not appear in authorization %q", challengeURL, authz.URL)
		failureIsFatal = true
		return
	}

	// A challenge might remain pending after we fail to complete it if the
	// server is still willing to retry it. Since we want to limit how long we
	// wait for a challenge to complete, we count the number of errors listed for
	// the challenge by the server. When the number of errors increase (or the
	// challenge goes valid), we consider that to be one attempt and stop.
	oldCount := countErrors(&oldCh)

	// Get responder ready.
	r, err := responder.New(responder.Config{
		Type:            oldCh.Type,
		Token:           oldCh.Token,
		AccountKey:      acct.PrivateKey,
		Hostname:        authz.Identifier.Value,
		ChallengeConfig: *ccfg,
	})
	if err != nil {
		// We couldn't even instantiate a responder for this challenge type,
		// so it cannot be completed in any successor authorization either.
		// This is a fatal failure.
		failureIsFatal = true
		log.Debuge(err, "challenge instantiation failed")
		return
	}

	err = r.Start()
	if err != nil {
		log.Debuge(err, "challenge start failed")
		return
	}

	defer r.Stop()

	// RESPOND
	err = rc.RespondToChallenge(ctx, acct, &oldCh, r.Validation()) //r.ValidationSigningKey()
	if err != nil {
		return
	}

	b := denet.Backoff{
		InitialDelay: 5 * time.Second,
		MaxDelay:     30 * time.Second,
	}

	for {
		// Wait until we have some suspicion that the challenge may have been
		// completed.
		log.Debugf("challenge %q (%q): waiting to poll", oldCh.URL, oldCh.Type)
		select {
		case <-ctx.Done():
			err = ctx.Err()
			return
		case <-r.RequestDetectedChan():
			log.Debugf("challenge %q (%q): request detected", oldCh.URL, oldCh.Type)
		case <-time.After(b.NextDelay()):
			log.Debugf("challenge %q (%q): periodically checking", oldCh.URL, oldCh.Type)
		}

		// We could reload just the challenge, but there's not much point, since
		// the challenges are embedded inline in the authorization, and this keeps
		// the authorization object up-to-date too.
		log.Debugf("challenge %q (%q): querying status", oldCh.URL, oldCh.Type)
		err = rc.WaitLoadAuthorization(ctx, acct, authz)
		if err != nil {
			return
		}

		authWasLoaded = true

		updatedCh, ok := findChallengeByURL(authz, challengeURL)
		if !ok {
			err = fmt.Errorf("challenge %q has disappeared from authorization %q", challengeURL, authz.URL)
			return
		}

		if updatedCh.Status == acmeapi.ChallengeValid {
			// Challenge is valid, we're done here.
			err = nil
			return
		}

		if updatedCh.Status.IsFinal() {
			// The challenge is final but not valid; there is no further prospect of
			// completing this challenge. The server has definitively rejected
			// the challenge, so this is a fatal failure.
			failureIsFatal = true
			err = util.NewWrapError(updatedCh.Error, "authorization %q challenge %q failed into final non-valid status %v", authz.URL, challengeURL, updatedCh.Status)
			log.Infoe(err, "unsuccessful challenge")
			return
		}

		// TODO: allow number of error-tries to be tolerated before bailing to be
		// configured; currently fix it at 1.
		if countErrors(&updatedCh) != oldCount {
			err = util.NewWrapError(updatedCh.Error, "authorization %q challenge %q failed", authz.URL, challengeURL)
			log.Infoe(err, "unsuccessful challenge")
			return
		}
	}
}

func findChallengeByURL(authz *acmeapi.Authorization, challengeURL string) (acmeapi.Challenge, bool) {
	for i := range authz.Challenges {
		if authz.Challenges[i].URL == challengeURL {
			return authz.Challenges[i], true
		}
	}
	return acmeapi.Challenge{}, false
}

func countErrors(ch *acmeapi.Challenge) int {
	if ch == nil || ch.Error == nil {
		return 0
	}
	n := len(ch.Error.Subproblem)
	if n == 0 {
		return 1
	}
	return n
}
