package deliver

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/Songmu/go-httpdate"
	"github.com/go-fed/httpsig"
	"github.com/sirupsen/logrus"
)

func compatibilityForHTTPSignature11(request *http.Request, algorithm httpsig.Algorithm) {
	signature := request.Header.Get("Signature")
	targetString := regexp.MustCompile("algorithm=\"hs2019\"")
	signature = targetString.ReplaceAllString(signature, string("algorithm=\""+algorithm+"\""))
	request.Header.Set("Signature", signature)
}

func appendSignature(request *http.Request, body *[]byte, KeyID string, privateKey *rsa.PrivateKey) error {
	request.Header.Set("Host", request.Host)

	signer, _, err := httpsig.NewSigner([]httpsig.Algorithm{httpsig.RSA_SHA256}, httpsig.DigestSha256, []string{httpsig.RequestTarget, "Host", "Date", "Digest", "Content-Type"}, httpsig.Signature, 60*60)
	if err != nil {
		return err
	}
	err = signer.SignRequest(privateKey, KeyID, request, *body)
	if err != nil {
		return err
	}
	compatibilityForHTTPSignature11(request, httpsig.RSA_SHA256) // Compatibility for Misskey <12.111.0
	return nil
}

func publishSend(spost map[string]interface{}, iserror bool) {
	if j, jerr := json.Marshal(spost); jerr != nil {
		logrus.Error("json error : ", jerr.Error())
	} else {
		RedisClient.Publish("event:send", j)
		if iserror {
			RedisClient.Publish("error:send", j)
		}
	}
}

func sendActivity(inboxURL string, KeyID string, body []byte, privateKey *rsa.PrivateKey) error {
	req, _ := http.NewRequest("POST", inboxURL, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/activity+json")
	req.Header.Set("User-Agent", fmt.Sprintf("%s (golang net/http; Activity-Relay %s; %s)", GlobalConfig.ServerServiceName(), version, GlobalConfig.ServerHostname().Host))
	req.Header.Set("Date", httpdate.Time2Str(time.Now()))
	spost := map[string]interface{}{
		"url":     req.URL.String(),
		"headers": req.Header,
		"body":    &body,
	}
	sigerr := appendSignature(req, &body, KeyID, privateKey)
	if sigerr != nil {
		spost["sigerr"] = sigerr.Error()
		publishSend(spost, true)
		return sigerr
	}
	starttime := time.Now()
	resp, err := HttpClient.Do(req)
	spost["elapsed"] = time.Since(starttime).Milliseconds()
	if err != nil {
		spost["clienterr"] = err.Error()
		publishSend(spost, true)
		return err
	}
	defer resp.Body.Close()

	respbody, readerr := io.ReadAll(resp.Body)
	spost["respbody"] = respbody
	if readerr != nil {
		spost["resperr"] = readerr.Error()
	}
	spost["statuscode"] = resp.StatusCode

	logrus.Debug(inboxURL, " ", resp.StatusCode)
	if resp.StatusCode/100 != 2 {
		publishSend(spost, true)
		return errors.New("Post " + inboxURL + ": " + resp.Status)
	}
	publishSend(spost, false)

	return nil
}
