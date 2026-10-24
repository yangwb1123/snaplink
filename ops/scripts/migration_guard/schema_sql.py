"""Bounded native catalog facets; no OID-dependent fingerprints or DDL execution."""
from .snapshot import identifier

ENVIRONMENT_SQL = """SELECT json_build_object('kind','environment','value',json_build_object(
 'server_version_num',current_setting('server_version_num')::int,'encoding',pg_encoding_to_char(d.encoding),
 'collate',d.datcollate,'ctype',d.datctype,'provider',d.datlocprovider,'icu_locale',d.daticulocale,
 'recorded_version',d.datcollversion,'actual_version',pg_database_collation_actual_version(d.oid)))::jsonb
 FROM pg_database d WHERE d.datname=current_database();"""

FACETS = {
 "columns": """SELECT a.attname AS name,a.attnum AS position,tn.nspname AS type_schema,t.typname AS type,
 a.atttypmod AS typmod,a.attnotnull AS not_null,a.attidentity AS identity,a.attgenerated AS generated,
 pg_get_expr(ad.adbin,ad.adrelid) AS default_expression,cn.nspname AS collation_schema,co.collname AS collation
 FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid JOIN pg_namespace tn ON tn.oid=t.typnamespace
 LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
 LEFT JOIN pg_collation co ON co.oid=a.attcollation LEFT JOIN pg_namespace cn ON cn.oid=co.collnamespace
 WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped""",
 "constraints": """SELECT k.conname AS name,k.contype AS type,pg_get_constraintdef(k.oid) AS definition,
 k.convalidated AS validated,k.condeferrable AS deferrable,k.condeferred AS initially_deferred,
 pn.nspname AS parent_schema,pc.relname AS parent_table,k.confmatchtype AS match_type,
 k.confupdtype AS on_update,k.confdeltype AS on_delete,
 ARRAY(SELECT a.attname FROM unnest(k.conkey) WITH ORDINALITY z(num,pos) JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=z.num ORDER BY z.pos) AS child_columns,
 ARRAY(SELECT a.attname FROM unnest(k.confkey) WITH ORDINALITY z(num,pos) JOIN pg_attribute a ON a.attrelid=k.confrelid AND a.attnum=z.num ORDER BY z.pos) AS parent_columns,
 ARRAY(SELECT ns.nspname||'.'||op.oprname FROM unnest(k.conpfeqop) WITH ORDINALITY z(num,pos) JOIN pg_operator op ON op.oid=z.num JOIN pg_namespace ns ON ns.oid=op.oprnamespace ORDER BY z.pos) AS equality_operators
 FROM pg_constraint k LEFT JOIN pg_class pc ON pc.oid=k.confrelid LEFT JOIN pg_namespace pn ON pn.oid=pc.relnamespace WHERE k.conrelid=c.oid""",
 "indexes": """SELECT ic.relname AS name,am.amname AS method,i.indisunique AS unique_index,i.indisprimary AS primary_index,
 i.indisvalid AS valid,i.indisready AS ready,i.indislive AS live,i.indnullsnotdistinct AS nulls_not_distinct,
 i.indnkeyatts AS key_columns,i.indnatts AS all_columns,pg_get_indexdef(i.indexrelid) AS definition,
 pg_get_expr(i.indpred,i.indrelid) AS predicate,pg_get_expr(i.indexprs,i.indrelid) AS expressions,
 ARRAY(SELECT ns.nspname||'.'||op.opcname FROM unnest(i.indclass::oid[]) WITH ORDINALITY z(num,pos) JOIN pg_opclass op ON op.oid=z.num JOIN pg_namespace ns ON ns.oid=op.opcnamespace ORDER BY z.pos) AS opclasses,
 ic.reloptions AS options FROM pg_index i JOIN pg_class ic ON ic.oid=i.indexrelid JOIN pg_am am ON am.oid=ic.relam WHERE i.indrelid=c.oid""",
 "collations": """SELECT a.attname AS column,ns.nspname AS schema,co.collname AS name,co.collprovider AS provider,
 co.collisdeterministic AS deterministic,co.collencoding AS encoding,co.collcollate AS collate,co.collctype AS ctype,
 co.colliculocale AS icu_locale,co.collversion AS recorded_version,pg_collation_actual_version(co.oid) AS actual_version
 FROM pg_attribute a JOIN pg_collation co ON co.oid=a.attcollation JOIN pg_namespace ns ON ns.oid=co.collnamespace
 WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped""",
 "sequences": """SELECT a.attname AS column,ns.nspname AS schema,sc.relname AS name,d.deptype AS dependency,
 tn.nspname AS type_schema,t.typname AS type,q.seqstart AS start,q.seqincrement AS increment,
 q.seqmax AS maximum,q.seqmin AS minimum,q.seqcache AS cache,q.seqcycle AS cycle
 FROM pg_depend d JOIN pg_class sc ON sc.oid=d.objid AND sc.relkind='S'
 JOIN pg_namespace ns ON ns.oid=sc.relnamespace JOIN pg_sequence q ON q.seqrelid=sc.oid
 JOIN pg_type t ON t.oid=q.seqtypid JOIN pg_namespace tn ON tn.oid=t.typnamespace
 JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=d.refobjsubid
 WHERE d.classid='pg_class'::regclass AND d.refclassid='pg_class'::regclass AND d.refobjid=c.oid AND d.deptype IN ('a','i')""",
 "hazards": """SELECT c.relpersistence AS persistence,am.amname AS access_method,c.reloptions AS options,
 (SELECT count(*) FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal) AS user_triggers,
 (SELECT count(*) FROM pg_rewrite r WHERE r.ev_class=c.oid) AS rules,
 (SELECT count(*) FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid) AS inheritance_edges,
 (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid) AS policies,
 (SELECT count(*) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND a.attisdropped) AS dropped_columns
 FROM pg_am am WHERE am.oid=c.relam""",
}


def facet_sql(facet, names):
    for name in names:
        identifier(name)
    selected = ",".join("'" + name + "'" for name in sorted(names))
    return ("SELECT json_build_object('kind','facet','facet','" + facet + "','tables',coalesce(json_agg("
            "json_build_object('table',c.relname,'records',(SELECT coalesce(json_agg(rec),'[]'::json) FROM (" + FACETS[facet] + ") rec))),"
            "'[]'::json))::jsonb FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='public' AND c.relkind='r' AND c.relname IN (" + selected + ");")


def inventory_sql(names):
    return ENVIRONMENT_SQL + "\n" + "\n".join(facet_sql(facet, names) for facet in FACETS) + "\n"
