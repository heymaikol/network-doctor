/* SPDX-License-Identifier: GPL-2.0-or-later */
bool ndoc_dplane_traced(struct zebra_dplane_ctx *ctx)
{
	return ndoc_enabled() && ctx->ndoc_route;
}
void ndoc_dplane(const char *event, struct zebra_dplane_ctx *ctx, uint32_t nlseq, int error,
		bool accepted)
{
	json_object *j;
	if (!ndoc_enabled() || !ctx->ndoc_route) return;
	j = ndoc_record(event);
	ndoc_ref(j, "operation_id", ndoc_epoch(), "operation", ctx->ndoc_operation);
	ndoc_ref(j, "route_id", ndoc_epoch(), "route", ctx->ndoc_route);
	ndoc_num(j, "generation", ctx->ndoc_generation);
	ndoc_num(j, "dplane_sequence", ctx->zd_seq);
	ndoc_num(j, "netlink_sequence", nlseq);
	ndoc_num(j, "vrf", ctx->zd_vrf_id);
	ndoc_num(j, "table", ctx->zd_table_id);
	ndoc_num(j, "nhg", ctx->u.rinfo.nhe.id);
	ndoc_num(j, "safi", ctx->u.rinfo.zd_safi);
	ndoc_prefix(j, "prefix", &ctx->u.rinfo.zd_dest);
	json_object_string_add(j, "operation", dplane_op2str(ctx->zd_op));
	json_object_string_add(j, "result", dplane_res2str(ctx->zd_status));
	json_object_int_add(j, "error", error);
	json_object_boolean_add(j, "accepted_generation", accepted);
	json_object_string_add(j, "hook", event);
	if (!strcmp(event, "operation")) {
		json_object *a = json_object_new_array();
		struct nexthop *nh;
		bool supported = ctx->u.rinfo.zd_dest.family == AF_INET &&
			ctx->u.rinfo.zd_safi == SAFI_UNICAST && !ctx->zd_vrf_id &&
			ctx->zd_table_id == 254 && !ctx->u.rinfo.zd_src.prefixlen &&
			!ctx->u.rinfo.backup_ng.nexthop && ctx->ndoc_leg_count > 0 &&
			ctx->ndoc_leg_count <= NDOC_LIMIT &&
			(ctx->u.rinfo.zd_type == ZEBRA_ROUTE_BGP ||
			 (ctx->u.rinfo.zd_type == ZEBRA_ROUTE_STATIC && ctx->ndoc_leg_count == 1) ||
			 ctx->u.rinfo.zd_type == ZEBRA_ROUTE_CONNECT || ctx->u.rinfo.zd_type == ZEBRA_ROUTE_LOCAL);
		for (ALL_NEXTHOPS_PTR(&ctx->u.rinfo.zd_ng, nh)) {
			if ((nh->type != NEXTHOP_TYPE_IPV4 && nh->type != NEXTHOP_TYPE_IPV4_IFINDEX &&
			     nh->type != NEXTHOP_TYPE_IFINDEX) || nh->nh_label || nh->nh_srv6 ||
			    nh->srte_color || nh->backup_num || nh->vrf_id || nh->weight > 1 ||
			    CHECK_FLAG(nh->flags, NEXTHOP_FLAG_ONLINK)) supported = false;
		}
		json_object_boolean_add(j, "supported", supported);
		for (unsigned i = 0; i < MIN(ctx->ndoc_leg_count, NDOC_LIMIT); i++) {
			json_object *ref = json_object_new_object();
			ndoc_num(ref, "leg", i);
			if (ctx->ndoc_resolutions[i])
				ndoc_ref(ref, "resolution_id", ndoc_epoch(), "resolution", ctx->ndoc_resolutions[i]);
			else json_object_object_add(ref, "resolution_id", NULL);
			json_object_array_add(a, ref);
		}
		ndoc_num(j, "source_leg_count", ctx->ndoc_leg_count);
		json_object_object_add(j, "resolution_refs", a);
	}
	ndoc_emit(j);
}
bool ndoc_dplane_matches(struct zebra_dplane_ctx *ctx, struct route_entry *re)
{
	return re && ctx->ndoc_route == re->ndoc_id &&
	       ctx->ndoc_generation == re->ndoc_generation && ctx->zd_seq == re->dplane_sequence;
}
