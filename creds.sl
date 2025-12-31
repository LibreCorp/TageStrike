$cols_base = "
    publics.username AS user,
    privates.data AS pass,
    privates.type AS ptype,
    cores.id AS id,
    cores.realm_id AS realm_id
";

$q_logins = "
SELECT 
    $cols_base,
    host(hosts.address) AS host,
    services.name AS sname,
    services.port AS port,
    services.proto AS proto
FROM metasploit_credential_cores AS cores
JOIN metasploit_credential_publics AS publics ON cores.public_id = publics.id
JOIN metasploit_credential_privates AS privates ON cores.private_id = privates.id
JOIN metasploit_credential_logins AS logins ON logins.core_id = cores.id
JOIN services ON logins.service_id = services.id
JOIN hosts ON services.host_id = hosts.id
WHERE hosts.workspace_id = \" + workspaceid + \"
";

$q_sessions = "
SELECT
    $cols_base,
    host(hosts.address) AS host,
    'station' AS sname,
    sessions.port AS port,
    'tcp' AS proto
FROM metasploit_credential_cores AS cores
JOIN metasploit_credential_publics AS publics ON cores.public_id = publics.id
JOIN metasploit_credential_privates AS privates ON cores.private_id = privates.id
JOIN metasploit_credential_origin_sessions AS orig_sess ON cores.origin_id = orig_sess.id
JOIN sessions ON orig_sess.session_id = sessions.id
JOIN hosts ON sessions.host_id = hosts.id
WHERE cores.origin_type = 'Metasploit::Credential::Origin::Session'
AND hosts.workspace_id = \" + workspaceid + \"
";

$q_manual = "
SELECT
    $cols_base,
    NULL AS host,
    '' AS sname,
    0 AS port,
    '' AS proto
FROM metasploit_credential_cores AS cores
JOIN metasploit_credential_publics AS publics ON cores.public_id = publics.id
JOIN metasploit_credential_privates AS privates ON cores.private_id = privates.id
WHERE cores.origin_type != 'Metasploit::Credential::Origin::Session'
AND cores.id NOT IN (SELECT core_id FROM metasploit_credential_logins)
";

@queries = @($q_logins, $q_sessions, $q_manual);

println(join(" UNION ", @queries));
