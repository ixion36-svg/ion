$baseUrl = 'http://127.0.0.1:8000'

function Test-Dashboard($username, $password, $expectedRole) {
    Write-Output "`n===== Testing: $username ($expectedRole) ====="
    try {
        # Login
        $body = "{`"username`":`"$username`",`"password`":`"$password`"}"
        $login = Invoke-WebRequest -Uri "$baseUrl/api/auth/login" -Method POST -ContentType 'application/json' -Body $body -UseBasicParsing -SessionVariable ws
        Write-Output "  Login: $($login.StatusCode)"

        # Get dashboard API data
        $dash = Invoke-WebRequest -Uri "$baseUrl/api/dashboard" -UseBasicParsing -WebSession $ws
        $dashData = $dash.Content | ConvertFrom-Json
        Write-Output "  Dashboard API: $($dash.StatusCode)"
        Write-Output "  User: $($dashData.user.username), Roles: $($dashData.user.roles -join ', ')"
        Write-Output "  Stats: templates=$($dashData.stats.templates_count), docs=$($dashData.stats.documents_count)"
        Write-Output "  ES connected: $($dashData.elasticsearch.connected), Alerts: $($dashData.elasticsearch.total_alerts)"

        # Get the HTML page
        $page = Invoke-WebRequest -Uri "$baseUrl/" -UseBasicParsing -WebSession $ws
        Write-Output "  Page load: $($page.StatusCode)"

        # Check which dashboard divs exist
        $hasAnalyst = $page.Content -match 'id="analyst-dashboard"'
        $hasLead = $page.Content -match 'id="lead-dashboard"'
        $hasEngineer = $page.Content -match 'id="engineer-dashboard"'
        $hasAdmin = $page.Content -match 'id="admin-dashboard"'
        $hasUser = $page.Content -match 'id="user-dashboard"'
        Write-Output "  HTML has: analyst=$hasAnalyst, lead=$hasLead, engineer=$hasEngineer, admin=$hasAdmin, user=$hasUser"

        # Check JS routing function exists
        $hasSetupLead = $page.Content -match 'setupLeadDashboard'
        $hasSetupEngineer = $page.Content -match 'setupEngineerDashboard'
        Write-Output "  JS functions: setupLeadDashboard=$hasSetupLead, setupEngineerDashboard=$hasSetupEngineer"

        # Check KPI row for lead
        $hasKPI = $page.Content -match 'kpi-row'
        $hasSeverityBars = $page.Content -match 'severity-bars'
        $hasTeamTable = $page.Content -match 'team-table'
        Write-Output "  Lead features: kpi-row=$hasKPI, severity-bars=$hasSeverityBars, team-table=$hasTeamTable"

        # Test team-metrics endpoint (for lead/admin)
        if ($expectedRole -eq 'lead' -or $expectedRole -eq 'admin') {
            try {
                $metrics = Invoke-WebRequest -Uri "$baseUrl/api/dashboard/team-metrics" -UseBasicParsing -WebSession $ws
                $metricsData = $metrics.Content | ConvertFrom-Json
                Write-Output "  Team metrics: open_cases=$($metricsData.open_cases), mttr=$($metricsData.mttr_hours), unassigned=$($metricsData.unassigned_alerts)"
                Write-Output "  Severity: critical=$($metricsData.cases_by_severity.critical), high=$($metricsData.cases_by_severity.high), medium=$($metricsData.cases_by_severity.medium), low=$($metricsData.cases_by_severity.low)"
                Write-Output "  Closures (7d): $($metricsData.closed_7d) / $($metricsData.created_7d) = $($metricsData.closure_rate_7d)%"
                Write-Output "  Assignees: $($metricsData.cases_by_assignee.Count), Recent closures: $($metricsData.recent_closures.Count)"
            } catch {
                Write-Output "  Team metrics ERROR: $($_.Exception.Message)"
            }
        }

        Write-Output "  PASS"
    } catch {
        Write-Output "  FAIL: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            Write-Output "  Response: $($reader.ReadToEnd())"
        }
    }
}

# Check which users exist
Write-Output "Checking available users..."
try {
    $body = '{"username":"admin","password":"admin2025"}'
    $login = Invoke-WebRequest -Uri "$baseUrl/api/auth/login" -Method POST -ContentType 'application/json' -Body $body -UseBasicParsing -SessionVariable adminWs
    $users = Invoke-WebRequest -Uri "$baseUrl/api/users" -UseBasicParsing -WebSession $adminWs
    $userData = $users.Content | ConvertFrom-Json
    foreach ($u in $userData) {
        Write-Output "  User: $($u.username) - Roles: $($u.roles -join ', ')"
    }
} catch {
    Write-Output "  Could not list users: $($_.Exception.Message)"
}

# Test each dashboard
Test-Dashboard 'admin' 'admin2025' 'admin'
Test-Dashboard 'lead1' 'user2025' 'lead'

# Try common analyst/engineer usernames
$analystNames = @('analyst1', 'analyst')
foreach ($name in $analystNames) {
    try {
        $body = "{`"username`":`"$name`",`"password`":`"user2025`"}"
        $test = Invoke-WebRequest -Uri "$baseUrl/api/auth/login" -Method POST -ContentType 'application/json' -Body $body -UseBasicParsing
        Test-Dashboard $name 'user2025' 'analyst'
        break
    } catch {
        Write-Output "`nSkipping $name (login failed)"
    }
}

$engineerNames = @('engineer1', 'engineer')
foreach ($name in $engineerNames) {
    try {
        $body = "{`"username`":`"$name`",`"password`":`"user2025`"}"
        $test = Invoke-WebRequest -Uri "$baseUrl/api/auth/login" -Method POST -ContentType 'application/json' -Body $body -UseBasicParsing
        Test-Dashboard $name 'user2025' 'engineering'
        break
    } catch {
        Write-Output "`nSkipping $name (login failed)"
    }
}

Write-Output "`n===== SUMMARY ====="
Write-Output "All dashboard tests complete."
