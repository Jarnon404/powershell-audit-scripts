BeforeAll {
    $RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
    $DocsRoot = Join-Path $RepoRoot "docs\scripts"

    $PowerShellScripts = Get-ChildItem $RepoRoot -Filter "*.ps1" -File |
        Sort-Object Name
}

Describe "Repository structure" {
    It "Contains at least one PowerShell script in repository root" {
        @($PowerShellScripts).Count | Should -BeGreaterThan 0
    }

    It "Has script documentation directory" {
        Test-Path $DocsRoot | Should -BeTrue
    }
}

Describe "PowerShell script syntax" {
    foreach ($Script in $PowerShellScripts) {
        It "Parses without syntax errors: $($Script.Name)" {
            $Tokens = $null
            $Errors = $null

            [System.Management.Automation.Language.Parser]::ParseFile(
                $Script.FullName,
                [ref]$Tokens,
                [ref]$Errors
            ) | Out-Null

            $Errors.Count | Should -Be 0
        }
    }
}

Describe "Comment-based help" {
    foreach ($Script in $PowerShellScripts) {
        $Content = Get-Content $Script.FullName -Raw

        It "Has SYNOPSIS: $($Script.Name)" {
            $Content | Should -Match '\.SYNOPSIS'
        }

        It "Has DESCRIPTION: $($Script.Name)" {
            $Content | Should -Match '\.DESCRIPTION'
        }

        It "Has DISCLAIMER or NOTES: $($Script.Name)" {
            $Content | Should -Match '(\.DISCLAIMER|\.NOTES)'
        }
    }
}

Describe "Script documentation" {
    foreach ($Script in $PowerShellScripts) {
        $ExpectedDoc = Join-Path $DocsRoot ($Script.BaseName + ".md")

        It "Has documentation file: $($Script.BaseName).md" {
            Test-Path $ExpectedDoc | Should -BeTrue
        }
    }
}

Describe "Public repository hygiene" {
    It "Does not contain generated output files" {
        $OutputFiles = Get-ChildItem $RepoRoot -Recurse -File |
            Where-Object {
                $_.FullName -notmatch '[\\/]\.git[\\/]' -and
                $_.FullName -notmatch '[\\/]\.github[\\/]' -and
                $_.Extension -match '^\.(csv|xlsx|html|json|log|zip|7z|bak|tmp)$'
            }

        $OutputFiles | Should -BeNullOrEmpty
    }

    It "Does not contain internal-looking example domains" {
        $Files = Get-ChildItem $RepoRoot -Recurse -File |
            Where-Object {
                $_.FullName -notmatch '[\\/]\.git[\\/]' -and
                $_.FullName -notmatch '[\\/]\.github[\\/]workflows[\\/]'
            }

        $Findings = foreach ($File in $Files) {
            $Content = Get-Content $File.FullName -Raw -ErrorAction SilentlyContinue

            if ($Content -match 'contoso\.local|\.local\b|\.lan\b|\.corp\b') {
                $File.FullName
            }
        }

        $Findings | Should -BeNullOrEmpty
    }
}
