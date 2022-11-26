package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-fed/httpsig"
	"github.com/yukimochi/Activity-Relay/models"
)

// Note that this always returns the body handed to it, even if there is an error.
// This is to assist in debugging connectivity/request issues.
func decodeActivity(request *http.Request) (*models.Activity, *models.Actor, []byte, error) {
	request.Header.Set("Host", request.Host)
	body, _ := io.ReadAll(request.Body)

	// Verify HTTPSignature
	verifier, err := httpsig.NewVerifier(request)
	if err != nil {
		return nil, nil, body, err
	}
	KeyID := verifier.KeyId()
	keyOwnerActor := new(models.Actor)
	err = keyOwnerActor.RetrieveRemoteActor(KeyID, fmt.Sprintf("%s (golang net/http; Activity-Relay %s; %s)", GlobalConfig.ServerServiceName(), version, GlobalConfig.ServerHostname().Host), ActorCache)
	if err != nil {
		return nil, nil, body, err
	}
	PubKey, err := models.ReadPublicKeyRSAFromString(keyOwnerActor.PublicKey.PublicKeyPem)
	if PubKey == nil {
		return nil, nil, body, errors.New("failed parse PublicKey from string")
	}
	if err != nil {
		return nil, nil, body, err
	}
	err = verifier.Verify(PubKey, httpsig.RSA_SHA256)
	if err != nil {
		return nil, nil, body, err
	}

	// Verify Digest
	givenDigest := request.Header.Get("Digest")
	hash := sha256.New()
	hash.Write(body)
	b := hash.Sum(nil)
	calculatedDigest := "SHA-256=" + base64.StdEncoding.EncodeToString(b)

	if givenDigest != calculatedDigest {
		return nil, nil, body, errors.New("digest header is mismatch")
	}

	// Parse Activity
	var activity models.Activity
	err = json.Unmarshal(body, &activity)
	if err != nil {
		return nil, nil, body, err
	}

	var remoteActor models.Actor
	err = remoteActor.RetrieveRemoteActor(activity.Actor, fmt.Sprintf("%s (golang net/http; Activity-Relay %s; %s)", GlobalConfig.ServerServiceName(), version, GlobalConfig.ServerHostname().Host), ActorCache)
	if err != nil {
		return nil, nil, body, err
	}

	return &activity, &remoteActor, body, nil
}
