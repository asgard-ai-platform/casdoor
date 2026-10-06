// Copyright 2022 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package captcha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/beego/beego/logs"
)

const ReCaptchaEnterpriseVerifyUrl = "https://recaptchaenterprise.googleapis.com/v1/projects/%s/assessments?key=%s"

// ReCaptchaEnterpriseProvider verifies tokens through reCAPTCHA Enterprise's
// assessments API instead of the legacy siteverify endpoint.
//
// This exists because the legacy endpoint cannot verify tokens from mobile
// apps. A key created in the GCP console for an iOS or Android application is
// issued without a legacy secret at all — there is simply no value to put in
// the `secret` field siteverify requires — so native clients can only be
// verified here. Web keys accept both, which is why the web flow can keep
// working unchanged while mobile moves over.
//
// Credentials are packed into the provider's existing columns rather than
// extending the schema:
//
//	ClientId     → the site key, echoed back in the assessment event
//	ClientSecret → "<gcp-project-id>:<api-key>"
//
// The project id is part of the URL, not a header, so it has to travel with
// the key.
type ReCaptchaEnterpriseProvider struct{}

func NewReCaptchaEnterpriseProvider() *ReCaptchaEnterpriseProvider {
	captcha := &ReCaptchaEnterpriseProvider{}
	return captcha
}

func (captcha *ReCaptchaEnterpriseProvider) VerifyCaptcha(token, clientId, clientSecret string) (bool, error) {
	projectId, apiKey, found := strings.Cut(clientSecret, ":")
	if !found || projectId == "" || apiKey == "" {
		return false, fmt.Errorf("reCAPTCHA Enterprise: client secret must be \"<gcp-project-id>:<api-key>\"")
	}

	reqBody, err := json.Marshal(map[string]interface{}{
		"event": map[string]interface{}{
			"token":   token,
			"siteKey": clientId,
		},
	})
	if err != nil {
		return false, err
	}

	resp, err := http.Post(
		fmt.Sprintf(ReCaptchaEnterpriseVerifyUrl, projectId, apiKey),
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	// The assessment answers two separate questions, and both must pass. A
	// token can be well-formed yet rejected (wrong site key, already redeemed,
	// expired), which shows up as valid=false rather than an HTTP error.
	type assessmentResponse struct {
		Name            string `json:"name"`
		TokenProperties struct {
			Valid              bool   `json:"valid"`
			InvalidReason      string `json:"invalidReason"`
			Action             string `json:"action"`
			Hostname           string `json:"hostname"`
			AndroidPackageName string `json:"androidPackageName"`
			IosBundleId        string `json:"iosBundleId"`
		} `json:"tokenProperties"`
		RiskAnalysis struct {
			Score   float64  `json:"score"`
			Reasons []string `json:"reasons"`
		} `json:"riskAnalysis"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	assessment := &assessmentResponse{}
	if err = json.Unmarshal(body, assessment); err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
		msg := assessment.Error.Message
		if msg == "" {
			msg = string(body)
		}
		return false, fmt.Errorf("reCAPTCHA Enterprise returned %d: %s", resp.StatusCode, msg)
	}

	// Log every verdict. A low score reaches the caller only as "Turing test
	// failed.", with neither the score nor Google's reasons for it, and the
	// token is single-use, so the assessment cannot be fetched again afterwards.
	// The token itself is not logged.
	tp, ra := assessment.TokenProperties, assessment.RiskAnalysis
	logs.Info("reCAPTCHA Enterprise assessment: siteKey=%s valid=%t invalidReason=%q score=%v reasons=%v action=%q androidPackageName=%q iosBundleId=%q hostname=%q assessment=%s",
		clientId, tp.Valid, tp.InvalidReason, ra.Score, ra.Reasons, tp.Action, tp.AndroidPackageName, tp.IosBundleId, tp.Hostname, assessment.Name)

	if !assessment.TokenProperties.Valid {
		reason := assessment.TokenProperties.InvalidReason
		if reason == "" {
			reason = "unknown"
		}
		return false, fmt.Errorf("reCAPTCHA Enterprise rejected the token: %s", reason)
	}

	// Score-based (v3) keys return 0.0–1.0, where higher is more likely human.
	// 0.5 is Google's documented default threshold and matches what the legacy
	// provider effectively enforced through siteverify.
	return assessment.RiskAnalysis.Score >= 0.5, nil
}
