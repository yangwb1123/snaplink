"""Catalog every database sequence in every schema; state/floor queries never write."""
from .snapshot import identifier

INVENTORY_SQL = """
SELECT coalesce(json_agg(x ORDER BY x.schema,x.name),'[]'::json) FROM (
 SELECT s.oid::bigint AS oid,ns.nspname AS schema,s.relname AS name,
 tn.nspname AS type_namespace,typ.typname AS type,q.seqstart AS start,q.seqincrement AS increment,
 q.seqmin AS minimum,q.seqmax AS maximum,q.seqcache AS cache,q.seqcycle AS cycle,
 (SELECT count(*) FROM pg_depend z WHERE z.classid='pg_class'::regclass AND z.objid=s.oid
  AND z.refclassid='pg_class'::regclass AND z.deptype IN ('a','i')) AS owner_count,
 n.nspname AS table_schema,t.relname AS table,a.attname AS column,d.deptype AS dependency,
 t.oid::bigint AS relation_oid,t.relkind AS relkind,t.relrowsecurity AS rls_enabled,t.relforcerowsecurity AS force_rls,
 an.nspname AS column_type_namespace,at.typname AS column_type,a.attnotnull AS not_null,a.attidentity AS column_identity,
 coalesce(pg_get_expr(ad.adbin,ad.adrelid)=format('%s(%L::regclass)','nextval',s.oid::regclass::text),false) AS default_matches,
 (SELECT count(*) FROM pg_depend z WHERE z.refclassid='pg_class'::regclass AND z.refobjid=s.oid
  AND z.classid='pg_attrdef'::regclass AND z.deptype='n') AS default_dependents,
 (SELECT count(*) FROM pg_depend z WHERE z.refclassid='pg_class'::regclass AND z.refobjid=s.oid
  AND NOT(z.classid='pg_attrdef'::regclass AND z.deptype='n')) AS other_dependents,
 (SELECT count(*) FROM pg_depend z WHERE z.classid='pg_class'::regclass AND z.objid=s.oid
  AND NOT((z.refclassid='pg_class'::regclass AND z.deptype IN ('a','i')) OR
   (z.refclassid='pg_namespace'::regclass AND z.refobjid=ns.oid AND z.deptype='n'))) AS other_dependencies
 FROM pg_class s JOIN pg_namespace ns ON ns.oid=s.relnamespace JOIN pg_sequence q ON q.seqrelid=s.oid
 JOIN pg_type typ ON typ.oid=q.seqtypid JOIN pg_namespace tn ON tn.oid=typ.typnamespace
 LEFT JOIN pg_depend d ON d.classid='pg_class'::regclass AND d.objid=s.oid AND d.refclassid='pg_class'::regclass AND d.deptype IN ('a','i')
 LEFT JOIN pg_class t ON t.oid=d.refobjid LEFT JOIN pg_namespace n ON n.oid=t.relnamespace
 LEFT JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=d.refobjsubid AND NOT a.attisdropped
 LEFT JOIN pg_type at ON at.oid=a.atttypid LEFT JOIN pg_namespace an ON an.oid=at.typnamespace
 LEFT JOIN pg_attrdef ad ON ad.adrelid=t.oid AND ad.adnum=a.attnum
 WHERE s.relkind='S'
 ORDER BY ns.nspname,s.relname LIMIT 101
) x;
"""


def inventory_frame_sql():
    return "SELECT json_build_object('kind','sequence_inventory','items',(" + INVENTORY_SQL.strip().removesuffix(';') + "))::jsonb;\n"


def state_sql(descriptor, framed=True):
    name = descriptor['name']
    table = identifier(descriptor['schema']) + '.' + identifier(name)
    fields = "'sequence','" + name + "','oid','" + table + "'::regclass::oid::text,'last_value',last_value::text,'is_called',is_called"
    if framed:
        fields = "'kind','sequence_state'," + fields
    return 'SELECT json_build_object(' + fields + ')::jsonb FROM ' + table + ';\n'


def bounds_sql(descriptor):
    name,column = descriptor['name'],identifier(descriptor['column'])
    table = identifier(descriptor['table_schema']) + '.' + identifier(descriptor['table'])
    return ("SELECT json_build_object('kind','sequence_bounds','sequence','" + name + "','rows',count(*),"
            "'nulls',count(*)-count(" + column + "),'minimum',min(" + column + ")::text,'maximum',max(" + column + ")::text)::jsonb FROM " + table + ';\n')


def scan_sql(items):
    sql = ''.join(state_sql(d) + bounds_sql(d) for d in items)
    return sql + "SELECT json_build_object('kind','complete','read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'))::jsonb;\nCOMMIT;\n"
