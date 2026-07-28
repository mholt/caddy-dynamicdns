// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dynamicdns

import (
	"context"
	"net/netip"
)

// IPUpdater is invoked when dynamic_dns decides the public IP address
// set has changed — the same trigger used to update DNS A/AAAA records
// (plus retries if a previous updater call failed). Implementations
// should be idempotent.
//
// Typical uses: edge-router firewall pinholes. DNS itself stays in App
// via dns.providers.
type IPUpdater interface {
	UpdateIPs(context.Context, []netip.Addr) error
}
