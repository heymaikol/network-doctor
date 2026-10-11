# FRR 10.7.0 OSPF instance without a router ID

These are `show ip ospf json` outputs from a one-router probe. The probe is
`../lab/unset-router-id.sh`, run once per mode with the FRR 10.7.0 RPM described
in `../README.md`. Nothing here came from a production network.

| File | Mode | What FRR printed |
| --- | --- | --- |
| `none.raw` | `router ospf`, no router ID, no IPv4 address on any interface | `"routerId":"0.0.0.0"`, with the instance running |
| `addr.raw` | as `none`, plus 10.9.9.9/32 on a dummy interface | `"routerId":"10.9.9.9"`, which zebra supplied |
| `absent.raw` | no `router ospf` instance | the echoed command and the prompt, with no JSON body |

The probe also has a `noinst` mode: an `interface d0` block and no `router ospf`
stanza, with the address of `addr`. It printed the same empty body as `absent`.
Its output is not committed.

FRR 10.7.0 source behind these outputs (`src/` of the release tree):

- `ospfd/ospfd.c:335`: `ospf_new_alloc` sets the router ID to 0.
- `ospfd/ospfd.c:148`, `:165-200`: the refresh returns while the instance is
  not running, and otherwise takes the static ID or the zebra ID.
- `ospfd/ospfd.c:458-459`: `ospf_new` sets `oi_running` and runs the refresh,
  so a configured instance counts as running before it has an ID.
- `zebra/router-id.c:61-84`: `router_id_get` starts from `INADDR_ANY` and takes an
  address only when an interface has one.
- `ospfd/ospf_vty.c:3069-3070`: the JSON `routerId` is `ospf->router_id`.
- `ospfd/ospf_vty.c:3494-3495`: no OSPF instance at all, so no output.
- `ospfd/ospf_vty.c:3536-3538`: the default VRF has no running instance while
  another instance exists, so `{}` is printed.

The `none` and `addr` runs match the source. The `absent` run matches
`ospf_vty.c:3494-3495`. The `{}` case, `ospf_vty.c:3536-3538`, is from the source
only. No capture here prints `{}` for `show ip ospf json`. The `{}` output in
`../noinst/` is for other commands.

`.collected_at` holds the UTC time before the query. It is the time the probe
recorded, not a value checked against any other source.
