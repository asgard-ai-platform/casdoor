// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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

package routers

import (
	"strings"

	"github.com/beego/beego/context"
)

// hstsValue is two years, matching the value the other Asgard services behind the same
// ALB already send.
const hstsValue = "max-age=63072000; includeSubDomains"

// isHttpsRequest reports whether the request reached the load balancer over HTTPS. TLS is
// terminated at the ALB, so the connection casdoor sees is plain HTTP and the original
// scheme only survives in X-Forwarded-Proto.
func isHttpsRequest(ctx *context.Context) bool {
	if proto := ctx.Input.Header("X-Forwarded-Proto"); proto != "" {
		return strings.EqualFold(proto, "https")
	}

	return ctx.Request.TLS != nil
}

// HstsFilter sets Strict-Transport-Security so browsers refuse to fall back to plain HTTP
// after the first visit. RFC 6797 requires browsers to ignore the header when it arrives
// over an insecure transport, so it is only sent for HTTPS requests.
//
// This has to be registered before StaticFilter: once a filter writes the response beego
// stops running the rest of the BeforeRouter chain, and the login pages that need the
// header are served as static files.
func HstsFilter(ctx *context.Context) {
	if isHttpsRequest(ctx) {
		ctx.Output.Header("Strict-Transport-Security", hstsValue)
	}
}
