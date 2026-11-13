// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"errors"
	"testing"
	"time"

	azv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

// TestRequesterExtrasPartitionCache verifies that two requesters differing
// only in their Extra fields never share cache entries — extras influence the
// SAR outcome, so omitting them from the key would leak decisions across
// principals.
func TestRequesterExtrasPartitionCache(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &fnReviewer{}
	reviewer.set(allowAll)
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	requesterA := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}, Extra: map[string][]string{"project": {"a"}}}
	requesterB := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}, Extra: map[string][]string{"project": {"b"}}}

	if _, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), requesterA); err != nil {
		t.Fatalf("requester A: unexpected error: %v", err)
	}
	if _, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), requesterA); err != nil {
		t.Fatalf("requester A repeat: unexpected error: %v", err)
	}
	if got := reviewer.calls.Load(); got != 1 {
		t.Fatalf("SAR Create ran %d times for requester A, want 1 (cache hit)", got)
	}

	if _, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), requesterB); err != nil {
		t.Fatalf("requester B: unexpected error: %v", err)
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times, want 2 (requester B must not inherit A's cached decision)", got)
	}
}

// TestCachedAllowNotLeakedAcrossNaiveCollision is the behavioral counterpart
// of the key-collision test: a principal whose identity fields concatenate to
// the same string as an authorized principal's must still be checked live and
// denied.
func TestCachedAllowNotLeakedAcrossNaiveCollision(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &fnReviewer{}
	// Only "aliceusers" holds the impersonation grant.
	reviewer.set(func(req *azv1.SubjectAccessReview) (*azv1.SubjectAccessReview, error) {
		req.Status = azv1.SubjectAccessReviewStatus{Allowed: req.Spec.User == "aliceusers"}
		return req, nil
	})
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	// Naive requester+resource+name concatenation renders both checks as
	// "aliceusers" + "users" + "bob" == "alice" + "users" + "usersbob".
	privileged := &user.DefaultInfo{Name: "aliceusers"}
	target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), privileged)
	if err != nil || target == nil {
		t.Fatalf("privileged requester: target = %+v, err = %v, want allow", target, err)
	}

	attacker := &user.DefaultInfo{Name: "alice"}
	target, err = sar.CheckAuthorizedForImpersonation(impersonateUserRequest("usersbob"), attacker)
	if target != nil || !errors.Is(err, ErrImpersonationNotAllowed) {
		t.Fatalf("colliding requester: target = %+v, err = %v, want denial (must not inherit cached allow)", target, err)
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times, want 2 (colliding identity must be checked live)", got)
	}
}

// TestCachedAllowNotInheritedAcrossUID verifies that two principals identical
// in name, groups, and extras but differing in UID never share a cached
// decision: the requester's UID is part of the submitted SAR spec and
// therefore of the cache key, so the second principal must be checked live
// and denied rather than inheriting the first principal's cached allow.
func TestCachedAllowNotInheritedAcrossUID(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	reviewer := &fnReviewer{}
	// Only the principal with UID "uid-allowed" holds the impersonation grant.
	reviewer.set(func(req *azv1.SubjectAccessReview) (*azv1.SubjectAccessReview, error) {
		req.Status = azv1.SubjectAccessReviewStatus{Allowed: req.Spec.UID == "uid-allowed"}
		return req, nil
	})
	sar := newCachedSAR(reviewer, 10*time.Second, 30*time.Second, clk)

	privileged := &user.DefaultInfo{Name: "mmosley", UID: "uid-allowed", Groups: []string{"group1"}}
	target, err := sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), privileged)
	if err != nil || target == nil || target.GetName() != "bob" {
		t.Fatalf("privileged principal: target = %+v, err = %v, want allow", target, err)
	}

	// Same name, groups, and extras — only the UID differs.
	imposter := &user.DefaultInfo{Name: "mmosley", UID: "uid-other", Groups: []string{"group1"}}
	target, err = sar.CheckAuthorizedForImpersonation(impersonateUserRequest("bob"), imposter)
	if target != nil || !errors.Is(err, ErrImpersonationNotAllowed) {
		t.Fatalf("differing-UID principal: target = %+v, err = %v, want denial (must not inherit cached allow)", target, err)
	}
	if got := reviewer.calls.Load(); got != 2 {
		t.Errorf("SAR Create ran %d times, want 2 (differing-UID principal must be checked live)", got)
	}
}

// TestDecisionCacheKeyCollisionResistance pins that identities and targets
// whose naive string concatenation would coincide produce distinct cache keys.
// A collision here would be a privilege escalation: one principal inheriting
// another's cached allow decision.
func TestDecisionCacheKeyCollisionResistance(t *testing.T) {
	type input struct {
		resource  string
		name      string
		requester user.Info
	}

	// Every entry must produce a key distinct from every other entry. Several
	// pairs are crafted so that concatenating their identity fields yields the
	// same string.
	tests := map[string]input{
		"alice impersonates bob": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"requester/name boundary shifted": {
			// Naive requester+resource+name concatenation collides with the
			// case above: "aliceusers"+"users"+"bob" vs "alice"+"users"+"usersbob".
			resource: "users", name: "usersbob",
			requester: &user.DefaultInfo{Name: "aliceusers"},
		},
		"boundary-shift counterpart": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "aliceusers"},
		},
		"two groups": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Groups: []string{"g1", "g2"}},
		},
		"one group with separator in name": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Groups: []string{"g1,g2"}},
		},
		"group boundary shifted": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Groups: []string{"g", "1g2"}},
		},
		"extra with two values": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"k": {"ab", "c"}}},
		},
		"extra value boundary shifted": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"k": {"a", "bc"}}},
		},
		"extra key/value boundary shifted": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"ka": {"b", "c"}}},
		},
		"group vs extra holding same strings": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"g1": {"g2"}}},
		},
		"same target as group kind": {
			resource: "groups", name: "bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"same target as uid kind": {
			resource: "uids", name: "bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"same target as extra kind": {
			resource: "userextras/team", name: "bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"subresource/name boundary shifted": {
			resource: "userextras/teambob", name: "",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"colon-joined concatenation, colon in requester": {
			// Colon-delimited requester:resource:name concatenation renders
			// this and the case below as "alice:users:bob".
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice:users"},
		},
		"colon-joined concatenation, colon in target": {
			resource: "users", name: "users:bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"space-joined concatenation, space in requester": {
			// Space-delimited concatenation renders this and the case below
			// as "alice users bob".
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice users"},
		},
		"space-joined concatenation, space in target": {
			resource: "users", name: "users bob",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"unicode requester": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "ålice"},
		},
		"unicode target, precomposed form": {
			// U+00F6 LATIN SMALL LETTER O WITH DIAERESIS.
			resource: "users", name: "böb",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"unicode target, decomposed form": {
			// "o" followed by U+0308 COMBINING DIAERESIS: canonically equivalent
			// to the precomposed case yet a distinct byte sequence, so it must
			// remain a distinct authorization question and key.
			resource: "users", name: "bo\u0308b",
			requester: &user.DefaultInfo{Name: "alice"},
		},
		"empty requester name": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: ""},
		},
		"empty group name": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Groups: []string{""}},
		},
		"empty extra value": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"k": {""}}},
		},
		"extra key with no values": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"k": {}}},
		},
		"requester uid": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", UID: "uid-1"},
		},
		"same identity differing only in uid": {
			resource: "users", name: "bob",
			requester: &user.DefaultInfo{Name: "alice", UID: "uid-2"},
		},
	}

	cache := newDecisionCache(time.Minute, time.Minute, decisionCacheSize, &fakeClock{})

	keys := map[string]string{}
	for testName, in := range tests {
		spec := impersonationReviewSpec(in.resource, in.name, in.requester)
		key, ok := cache.key(&spec)
		if !ok {
			t.Fatalf("%s: key() not cacheable, want cacheable", testName)
		}
		if prev, exists := keys[key]; exists {
			t.Errorf("cache key collision between %q and %q: %s", prev, testName, key)
		}
		keys[key] = testName
	}
}
