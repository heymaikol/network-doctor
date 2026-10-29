/* SPDX-License-Identifier: GPL-2.0-or-later */
static void ndoc_bgp_path(struct bgp_path_info *pi, struct zapi_route *api, unsigned leg)
{
	struct peer *peer = pi->peer;
	struct ndoc_contributor *c;
	struct zapi_nexthop *nh = &api->nexthops[leg];
	json_object *j;
	char address[INET6_ADDRSTRLEN];
	if (!ndoc_enabled()) return;
	if (api->prefix.family != AF_INET || api->safi != SAFI_UNICAST || api->vrf_id ||
	    (api->tableid && api->tableid != 254) || leg >= NDOC_LIMIT ||
	    peer->sort != BGP_PEER_EBGP || sockunion_family(&peer->connection->su) != AF_INET ||
	    !peer->ndoc_session || pi->addpath_rx_id ||
	    CHECK_FLAG(pi->flags, BGP_PATH_STALE) || nh->type != NEXTHOP_TYPE_IPV4 ||
	    nh->flags || nh->srte_color || nh->weight || nh->ifindex || nh->vrf_id ||
	    peer->bgp->table_map[AFI_IP][SAFI_UNICAST].name ||
	    (leg && memcmp(&nh->gate.ipv4, &api->nexthops[0].gate.ipv4, sizeof(struct in_addr)))) {
		api->ndoc_bad = true;
		return;
	}
	if (!pi->ndoc_id) pi->ndoc_id = ndoc_next();
	if (!peer->ndoc_id) peer->ndoc_id = ndoc_next();
	c = &api->ndoc.paths[api->ndoc.count++];
	c->path = pi->ndoc_id;
	c->peer = peer->ndoc_id;
	c->session = peer->ndoc_session;
	c->revision = ++pi->ndoc_revision;
	c->leg = leg;
	j = ndoc_record("bgp_path");
	ndoc_ref(j, "path_id", ndoc_epoch(), "path", c->path);
	ndoc_ref(j, "peer_id", ndoc_epoch(), "peer", c->peer);
	ndoc_ref(j, "session_id", ndoc_epoch(), "session", c->session);
	ndoc_num(j, "revision", c->revision);
	ndoc_num(j, "vrf", api->vrf_id);
	ndoc_num(j, "table", api->tableid ? api->tableid : 254);
	ndoc_num(j, "safi", api->safi);
	ndoc_prefix(j, "prefix", &api->prefix);
	inet_ntop(AF_INET, &peer->connection->su.sin.sin_addr, address, sizeof(address));
	json_object_string_add(j, "peer_address", address);
	json_object_string_add(j, "as_path", pi->attr->aspath->str);
	inet_ntop(AF_INET, &nh->gate.ipv4, address, sizeof(address));
	json_object_string_add(j, "nexthop", address);
	ndoc_num(j, "remote_as", peer->as);
	ndoc_num(j, "local_as", peer->local_as);
	json_object_boolean_add(j, "valid", CHECK_FLAG(pi->flags, BGP_PATH_VALID));
	json_object_boolean_add(j, "stale", CHECK_FLAG(pi->flags, BGP_PATH_STALE));
	json_object_boolean_add(j, "selected", CHECK_FLAG(pi->flags, BGP_PATH_SELECTED));
	json_object_boolean_add(j, "multipath", CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH));
	json_object_string_add(j, "hook", "bgp_zebra_announce_parse_nexthop");
	ndoc_emit(j);
}
static void ndoc_bgp_submit(struct zapi_route *api)
{
	json_object *j;
	if (!ndoc_enabled()) return;
	if (api->ndoc_bad || !api->ndoc.count || api->ndoc.count != api->nexthop_num) {
		api->ndoc.count = 0;
		j = ndoc_record("refusal");
		ndoc_prefix(j, "prefix", &api->prefix);
		json_object_string_add(j, "reason", "unsupported BGP feature or incomplete contributor set");
		ndoc_emit(j);
		return;
	}
	strlcpy(api->ndoc.epoch, ndoc_epoch(), sizeof(api->ndoc.epoch));
	api->ndoc.announcement = ndoc_next();
	SET_FLAG(api->message, ZAPI_MESSAGE_NETDOC);
	j = ndoc_record("bgp_submission");
	ndoc_paths(j, &api->ndoc);
	ndoc_prefix(j, "prefix", &api->prefix);
	ndoc_num(j, "vrf", api->vrf_id);
	ndoc_num(j, "table", api->tableid ? api->tableid : 254);
	ndoc_num(j, "safi", api->safi);
	json_object_string_add(j, "hook", "bgp_zebra_announce_actual");
	ndoc_emit(j);
}
