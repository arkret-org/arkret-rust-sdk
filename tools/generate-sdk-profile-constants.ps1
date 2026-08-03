param(
    [string]$ArtifactsDir = (Join-Path $PSScriptRoot "..\..\arkret-spec\spec\v1\artifacts"),
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\crates\policy\src\generated\profiles.rs")
)

. (Join-Path $PSScriptRoot 'utf8-byte-order.ps1')

# Emits crates/policy/src/generated/profiles.rs from
# arkret-spec/spec/v1/artifacts/profiles/conformance-profiles.json and
# arkret-spec/spec/v1/artifacts/registry/reducer-profile-registry.json.
#
# Outputs:
#   * `PROFILE_IDS`             — sorted byte-ordered slice of every declared
#                                 profile id.
#   * `is_profile_id`           — membership helper.
#   * `REDUCER_PROFILE_IDS`     — sorted active Realm reducer profiles.
#   * `REDUCER_PROFILE_UPGRADE_EDGES` — registered directed upgrade edges.
#   * `is_reducer_profile_id` / `can_upgrade_reducer_profile` — lookups.
#   * `ProfileRole`             — enum mirroring the spec layer's
#                                 `profile_roles` value set
#                                 (`client` / `server` / `gateway` /
#                                 `directory` / `admin` / `interop`).
#   * `PROFILE_ROLES`           — sorted `(profile_id, ProfileRole)` table.
#   * `profile_role`            — lookup helper.
#   * `profile_ids_with_role`   — reverse lookup.

$profilesPath = Join-Path $ArtifactsDir "profiles\conformance-profiles.json"
if (!(Test-Path -LiteralPath $profilesPath)) {
    throw "conformance profile artifact not found: $profilesPath"
}

$raw = Get-Content -LiteralPath $profilesPath -Raw
$artifact = $raw | ConvertFrom-Json
$digest = (Get-FileHash -LiteralPath $profilesPath -Algorithm SHA256).Hash.ToLowerInvariant()
$reducerProfilesPath = Join-Path $ArtifactsDir "registry\reducer-profile-registry.json"
if (!(Test-Path -LiteralPath $reducerProfilesPath)) {
    throw "reducer profile registry artifact not found: $reducerProfilesPath"
}
$reducerArtifact = Get-Content -LiteralPath $reducerProfilesPath -Raw | ConvertFrom-Json
$reducerDigest = (Get-FileHash -LiteralPath $reducerProfilesPath -Algorithm SHA256).Hash.ToLowerInvariant()
$activeReducerProfiles = @($reducerArtifact.profiles | Where-Object { $_.status -eq 'active' })
foreach ($profile in $activeReducerProfiles) {
    if ([string]::IsNullOrWhiteSpace([string]$profile.profile_id)) {
        throw 'active reducer profile is missing profile_id'
    }
    if ([string]$profile.profile_id -notmatch '^ak\.reducer(?:\.[a-z0-9][a-z0-9_.-]*)?\.v[0-9]+$') {
        throw "invalid reducer profile id: $($profile.profile_id)"
    }
}

$activeReducerProfileIds = @($activeReducerProfiles | ForEach-Object { [string]$_.profile_id })
if (($activeReducerProfileIds | Sort-Object -Unique).Count -ne $activeReducerProfileIds.Count) {
    throw 'duplicate active reducer profile id'
}
$activeReducerProfileIds = Sort-Utf8ByteLexicographic -Values $activeReducerProfileIds
$activeReducerProfileSet = @{}
foreach ($profileId in $activeReducerProfileIds) {
    $activeReducerProfileSet[$profileId] = $true
}
$upgradeEdges = New-Object System.Collections.Generic.List[object]
foreach ($profile in $activeReducerProfiles) {
    $source = [string]$profile.profile_id
    foreach ($targetValue in @($profile.upgrade_edges)) {
        $target = [string]$targetValue
        if (!$activeReducerProfileSet.ContainsKey($target)) {
            throw "reducer profile $source has an upgrade edge to unknown or inactive profile $target"
        }
        $upgradeEdges.Add([PSCustomObject]@{ Source = $source; Target = $target }) | Out-Null
    }
}
$upgradeEdges = @($upgradeEdges | Sort-Object Source, Target)

# Collect ids from a regex pass first, so we still notice ids that are
# referenced without a profile_roles entry (e.g. transitional candidates).
$idsFromRegex = Sort-Utf8ByteLexicographic -Values @([regex]::Matches($raw, 'ak\.profile\.[A-Za-z0-9_.-]+\.v[0-9]+') |
    ForEach-Object { $_.Value })

if ($null -eq $artifact.profile_roles) {
    throw "conformance profile artifact missing top-level 'profile_roles' object"
}

$rolesObject = $artifact.profile_roles
$roleById = @{}
foreach ($prop in $rolesObject.PSObject.Properties) {
    $roleById[$prop.Name] = [string]$prop.Value
}
$sortedRoleIds = Sort-Utf8ByteLexicographic -Values @($roleById.Keys)
$rolesEntries = @($sortedRoleIds | ForEach-Object {
    [PSCustomObject]@{ Id = $_; Role = $roleById[$_] }
})

# Validate role values against the documented enum.
$allowedRoles = @('client', 'server', 'gateway', 'directory', 'admin', 'interop')
foreach ($entry in $rolesEntries) {
    if ($allowedRoles -notcontains $entry.Role) {
        throw "profile $($entry.Id) has unsupported role $($entry.Role); allowed: $($allowedRoles -join ',')"
    }
}

# Every id in profile_roles MUST appear in the regex-derived id list (sanity
# check: keeps generator from accepting roles for ids that aren't declared
# anywhere else in the artifact).
foreach ($entry in $rolesEntries) {
    if ($idsFromRegex -notcontains $entry.Id) {
        throw "profile_roles references id $($entry.Id) which is not present in the artifact body"
    }
}

function ConvertTo-RoleVariant {
    param([string]$Role)
    switch ($Role) {
        'client'    { 'Client' }
        'server'    { 'Server' }
        'gateway'   { 'Gateway' }
        'directory' { 'Directory' }
        'admin'     { 'Admin' }
        'interop'   { 'Interop' }
        default     { throw "unsupported role $Role" }
    }
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("//! Generated conformance profile identifiers and role table.") | Out-Null
$lines.Add("//!") | Out-Null
$lines.Add("//! @generated by tools/generate-sdk-profile-constants.ps1 from the Arkret Spec") | Out-Null
$lines.Add("//! conformance profile and reducer profile registries; do not edit by hand.") | Out-Null
$lines.Add("//! Conformance input version: $($artifact.version); sha256=$digest; profiles=$($idsFromRegex.Count).") | Out-Null
$lines.Add("//! Reducer input version: $($reducerArtifact.version); sha256=$reducerDigest; active_profiles=$($activeReducerProfileIds.Count).") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("pub const PROFILE_IDS: &[&str] = &[") | Out-Null
foreach ($id in $idsFromRegex) {
    $lines.Add("    `"$id`",") | Out-Null
}
$lines.Add("];") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("pub fn is_profile_id(value: &str) -> bool {") | Out-Null
$lines.Add("    PROFILE_IDS.contains(&value)") | Out-Null
$lines.Add("}") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("/// Active Realm reducer profiles generated from the Spec registry.") | Out-Null
$lines.Add("pub const REDUCER_PROFILE_IDS: &[&str] = &[") | Out-Null
foreach ($profileId in $activeReducerProfileIds) {
    $lines.Add("    `"$profileId`",") | Out-Null
}
$lines.Add("];") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("/// Directed reducer-profile upgrades registered by the source profile.") | Out-Null
$lines.Add("pub const REDUCER_PROFILE_UPGRADE_EDGES: &[(&str, &str)] = &[") | Out-Null
foreach ($edge in $upgradeEdges) {
    $lines.Add("    (`"$($edge.Source)`", `"$($edge.Target)`"),") | Out-Null
}
$lines.Add("];") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("/// Returns whether the profile is an active Realm reducer profile.") | Out-Null
$lines.Add("pub fn is_reducer_profile_id(profile_id: &str) -> bool {") | Out-Null
$lines.Add("    REDUCER_PROFILE_IDS.binary_search(&profile_id).is_ok()") | Out-Null
$lines.Add("}") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("/// Returns whether the source profile registers a direct upgrade to target.") | Out-Null
$lines.Add("pub fn can_upgrade_reducer_profile(source: &str, target: &str) -> bool {") | Out-Null
$lines.Add("    REDUCER_PROFILE_UPGRADE_EDGES.contains(&(source, target))") | Out-Null
$lines.Add("}") | Out-Null
$lines.Add("") | Out-Null
$lines.Add('/// Spec-layer `profile_roles` enum: every declared profile id is partitioned') | Out-Null
$lines.Add('/// into exactly one of these roles. SDK manifests, client-side feature') | Out-Null
$lines.Add('/// negotiation, and conformance loaders MUST consult this table before') | Out-Null
$lines.Add('/// claiming a profile as locally implemented.') | Out-Null
$lines.Add("#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]") | Out-Null
$lines.Add("pub enum ProfileRole {") | Out-Null
$lines.Add("    Client,") | Out-Null
$lines.Add("    Server,") | Out-Null
$lines.Add("    Gateway,") | Out-Null
$lines.Add("    Directory,") | Out-Null
$lines.Add("    Admin,") | Out-Null
$lines.Add("    Interop,") | Out-Null
$lines.Add("}") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("impl ProfileRole {") | Out-Null
$lines.Add("    pub fn as_str(self) -> &'static str {") | Out-Null
$lines.Add("        match self {") | Out-Null
$lines.Add("            Self::Client => `"client`",") | Out-Null
$lines.Add("            Self::Server => `"server`",") | Out-Null
$lines.Add("            Self::Gateway => `"gateway`",") | Out-Null
$lines.Add("            Self::Directory => `"directory`",") | Out-Null
$lines.Add("            Self::Admin => `"admin`",") | Out-Null
$lines.Add("            Self::Interop => `"interop`",") | Out-Null
$lines.Add("        }") | Out-Null
$lines.Add("    }") | Out-Null
$lines.Add("}") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("impl std::str::FromStr for ProfileRole {") | Out-Null
$lines.Add("    type Err = ();") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("    fn from_str(value: &str) -> Result<Self, Self::Err> {") | Out-Null
$lines.Add("        match value {") | Out-Null
$lines.Add("            `"client`" => Ok(Self::Client),") | Out-Null
$lines.Add("            `"server`" => Ok(Self::Server),") | Out-Null
$lines.Add("            `"gateway`" => Ok(Self::Gateway),") | Out-Null
$lines.Add("            `"directory`" => Ok(Self::Directory),") | Out-Null
$lines.Add("            `"admin`" => Ok(Self::Admin),") | Out-Null
$lines.Add("            `"interop`" => Ok(Self::Interop),") | Out-Null
$lines.Add("            _ => Err(()),") | Out-Null
$lines.Add("        }") | Out-Null
$lines.Add("    }") | Out-Null
$lines.Add("}") | Out-Null
$lines.Add("") | Out-Null
$lines.Add('/// Sorted `(profile_id, ProfileRole)` table mirroring') | Out-Null
$lines.Add('/// `conformance-profiles.json#/profile_roles`. The order matches Rust''s') | Out-Null
$lines.Add('/// byte-ordered `str::cmp` so binary search is valid.') | Out-Null
$lines.Add("pub const PROFILE_ROLES: &[(&str, ProfileRole)] = &[") | Out-Null
foreach ($entry in $rolesEntries) {
    $variant = ConvertTo-RoleVariant -Role $entry.Role
    $lines.Add("    (`"$($entry.Id)`", ProfileRole::$variant),") | Out-Null
}
$lines.Add("];") | Out-Null
$lines.Add("") | Out-Null
$lines.Add('/// Returns the spec-declared role for `profile_id`, if any.') | Out-Null
$lines.Add("pub fn profile_role(profile_id: &str) -> Option<ProfileRole> {") | Out-Null
$lines.Add("    PROFILE_ROLES") | Out-Null
$lines.Add("        .binary_search_by(|(id, _)| (*id).cmp(profile_id))") | Out-Null
$lines.Add("        .ok()") | Out-Null
$lines.Add("        .map(|index| PROFILE_ROLES[index].1)") | Out-Null
$lines.Add("}") | Out-Null
$lines.Add("") | Out-Null
$lines.Add('/// Returns every profile id whose spec role is `role`, in sorted order.') | Out-Null
$lines.Add("pub fn profile_ids_with_role(role: ProfileRole) -> Vec<&'static str> {") | Out-Null
$lines.Add("    PROFILE_ROLES") | Out-Null
$lines.Add("        .iter()") | Out-Null
$lines.Add("        .filter(|(_, r)| *r == role)") | Out-Null
$lines.Add("        .map(|(id, _)| *id)") | Out-Null
$lines.Add("        .collect()") | Out-Null
$lines.Add("}") | Out-Null

Set-Content -LiteralPath $OutputPath -Value ($lines -join [Environment]::NewLine) -NoNewline
& rustfmt +nightly --edition 2024 $OutputPath
if ($LASTEXITCODE -ne 0) { throw "rustfmt failed for $OutputPath" }
Write-Host "Wrote $OutputPath ($($idsFromRegex.Count) ids, $($rolesEntries.Count) roles)"
