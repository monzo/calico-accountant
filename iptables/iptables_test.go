package iptables

import (
	"io"
	"strings"
	"testing"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var interfaceToWorkload = map[string]*apiv3.WorkloadEndpoint{
	"cali5125b8e5d77": {
		ObjectMeta: v1.ObjectMeta{
			Labels: map[string]string{
				"app": "bar",
			},
		},
		Spec: apiv3.WorkloadEndpointSpec{
			Pod:        "foo",
			IPNetworks: []string{"127.0.0.1/32"},
		},
	},
}

func TestParseFrom(t *testing.T) {
	type args struct {
		stdout              io.Reader
		interfaceToWorkload map[string]*apiv3.WorkloadEndpoint
	}
	tests := []struct {
		name    string
		args    args
		want    []*Result
		wantErr bool
	}{
		{
			name: "Parse correctly",
			args: args{
				stdout: strings.NewReader(`
[0:0] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:OuV4ONPRxEzXLeFe" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
[0:0] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:eJTvIhsT4VBx2eYR" -m conntrack --ctstate INVALID -j DROP
[12:720] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:HqDZuW76n3mdpCix" -j MARK --set-xmark 0x0/0x10000
[3:180] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:Zk6CbRlMMcKBWZg9" -m comment --comment "Start of policies" -j MARK --set-xmark 0x0/0x20000
[3:180] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:yWm8oY1YDuoYpkS6" -m mark --mark 0x0/0x20000 -j cali-pi-_hvIhg5e42MGXRa9paIF
[3:180] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:RnZHt9r_TDuk8NI7" -m comment --comment "Return if policy accepted" -m mark --mark 0x10000/0x10000 -j RETURN
[0:0] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:0HKmZy_mh8JT1Tl6" -m comment --comment "Drop if no policies passed packet" -m mark --mark 0x0/0x20000 -j DROP
[0:0] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:Z9Q29hxQp47qKVD4" -j cali-pri-kns.default
[0:0] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:TZFwnUkg2Qa27CXQ" -m comment --comment "Return if profile accepted" -m mark --mark 0x10000/0x10000 -j RETURN
[0:0] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:6b_y1gnlt2WO7muw" -m comment --comment "Drop if no profiles matched" -j DROP
[5:200] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:vFlDFrJ9Qkfz5bmD" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
[0:0] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:PYEqgsq3qaoejnWB" -m conntrack --ctstate INVALID -j DROP
[2:164] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:RjO_YJSWr911DY6T" -j MARK --set-xmark 0x0/0x10000
[2:164] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:reCQdsaa0txrA5aZ" -m comment --comment "Start of policies" -j MARK --set-xmark 0x0/0x20000
[2:164] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:GB6NmH8AJXUChNx0" -m mark --mark 0x0/0x20000 -j cali-po-_hvIhg5e42MGXRa9paIF
[0:0] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:EAx49aLc--OzcnGb" -m comment --comment "Return if policy accepted" -m mark --mark 0x10000/0x10000 -j RETURN
[2:164] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:mFJHSWPsX6BjHV5u" -m comment --comment "Drop if no policies passed packet" -m mark --mark 0x0/0x20000 -j DROP
[0:0] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:3sdhKBP7w38yxwGG" -j cali-pro-kns.default
[0:0] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:emE9qPqe4hA5HBPo" -m comment --comment "Return if profile accepted" -m mark --mark 0x10000/0x10000 -j RETURN
[0:0] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:s2Jrc8hOvqYYH_jj" -m comment --comment "Drop if no profiles matched" -j DROP
`),
				interfaceToWorkload: interfaceToWorkload,
			},
			want: []*Result{
				{
					PodName:     "foo",
					AppLabel:    "bar",
					PodIP:       "127.0.0.1",
					ChainType:   ToWorkLoad,
					CountType:   Accept,
					PacketCount: 3,
					Target:      "cali-pi-_hvIhg5e42MGXRa9paIF",
				}, {
					PodName:     "foo",
					AppLabel:    "bar",
					PodIP:       "127.0.0.1",
					ChainType:   ToWorkLoad,
					CountType:   Drop,
					PacketCount: 0,
					Target:      "DROP",
				},
				{
					PodName:     "foo",
					AppLabel:    "bar",
					PodIP:       "127.0.0.1",
					ChainType:   FromWorkLoad,
					CountType:   Accept,
					PacketCount: 0,
					Target:      "cali-po-_hvIhg5e42MGXRa9paIF",
				}, {
					PodName:     "foo",
					AppLabel:    "bar",
					PodIP:       "127.0.0.1",
					ChainType:   FromWorkLoad,
					CountType:   Drop,
					PacketCount: 2,
					Target:      "DROP",
				},
			},
		}, {
			name: "Ignore invalid counts",
			args: args{
				stdout: strings.NewReader(`
[-1:180] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:yWm8oY1YDuoYpkS6" -m mark --mark 0x0/0x20000 -j cali-pi-_hvIhg5e42MGXRa9paIF
[-1:180] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:RnZHt9r_TDuk8NI7" -m comment --comment "Return if policy accepted" -m mark --mark 0x10000/0x10000 -j RETURN
[-1:0] -A cali-tw-cali5125b8e5d77 -m comment --comment "cali:0HKmZy_mh8JT1Tl6" -m comment --comment "Drop if no policies passed packet" -m mark --mark 0x0/0x20000 -j DROP
`),
				interfaceToWorkload: interfaceToWorkload,
			},
			want: []*Result{},
		}, {
			name: "Ignore invalid target on drop",
			args: args{
				stdout: strings.NewReader(`
[2:164] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:mFJHSWPsX6BjHV5u" -m comment --comment "Drop if no policies passed packet" -m mark --mark 0x0/0x20000 -j RETURN
`),
				interfaceToWorkload: interfaceToWorkload,
			},
			want: []*Result{},
		}, {
			name: "Ignore if interface not found",
			args: args{
				stdout: strings.NewReader(`
[2:164] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:mFJHSWPsX6BjHV5u" -m comment --comment "Drop if no policies passed packet" -m mark --mark 0x0/0x20000 -j DROP
`),
			},
			want: []*Result{},
		}, {
			name: "Ignore if number overflows",
			args: args{
				stdout: strings.NewReader(`
[9223372036854775808:164] -A cali-fw-cali5125b8e5d77 -m comment --comment "cali:mFJHSWPsX6BjHV5u" -m comment --comment "Drop if no policies passed packet" -m mark --mark 0x0/0x20000 -j DROP
`),
				interfaceToWorkload: interfaceToWorkload,
			},
			want: []*Result{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFrom(tt.args.stdout, tt.args.interfaceToWorkload)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}

			require.Equal(t, tt.want, got)
		})
	}
}
