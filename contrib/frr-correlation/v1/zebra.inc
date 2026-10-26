/* SPDX-License-Identifier: GPL-2.0-or-later */
static void ndoc_selection(rib_dest_t *dest, struct route_entry *re,
			   struct route_entry *old, const struct prefix *p)
{
	json_object *j;
	if (!ndoc_enabled()) return;
	if (!dest->ndoc_id) dest->ndoc_id = ndoc_next();
	j = ndoc_record("selection");
	ndoc_ref(j, "destination_id", ndoc_epoch(), "destination", dest->ndoc_id);
	if (re) ndoc_ref(j, "route_id", ndoc_epoch(), "route", re->ndoc_id);
	else json_object_object_add(j, "route_id", NULL);
	ndoc_num(j, "generation", re ? re->ndoc_generation : 0);
	if (old) ndoc_ref(j, "replaces_route_id", ndoc_epoch(), "route", old->ndoc_id);
	else json_object_object_add(j, "replaces_route_id", NULL);
	ndoc_num(j, "selection_generation", ++dest->ndoc_selection);
	ndoc_prefix(j, "prefix", p);
	ndoc_emit(j);
}
void ndoc_zebra_route(const char *event, struct route_entry *re, const struct prefix *p)
{
	json_object *j;
	if (!ndoc_enabled()) return;
	j = ndoc_record(event);
	ndoc_ref(j, "route_id", ndoc_epoch(), "route", re->ndoc_id);
	ndoc_num(j, "generation", re->ndoc_generation);
	ndoc_prefix(j, "prefix", p);
	ndoc_num(j, "vrf", re->vrf_id);
	ndoc_num(j, "table", re->table);
	ndoc_num(j, "safi", re->ndoc_safi);
	json_object_string_add(j, "origin", zebra_route_string(re->type));
	ndoc_paths(j, &re->ndoc);
	json_object_string_add(j, "hook", "zebra_rib");
	ndoc_emit(j);
}
