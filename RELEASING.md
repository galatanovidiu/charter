# Releasing Charter

Charter uses an artifact-first release process. The verified `charter.zip` is the GitHub release asset, and its extracted `charter/` directory is the source for WordPress.org Subversion.

## Prepare the release

1. Choose the bare semantic version for the release:

    ```bash
    RELEASE_VERSION=0.1.1
    ```

2. Update the npm manifest and lockfile together:

    ```bash
    npm version --no-git-tag-version "${RELEASE_VERSION}"
    ```

3. Update the plugin header and `CHARTER_VERSION` in `charter.php`, the Stable Tag and current changelog entry in `readme.txt`, and the full history in `CHANGELOG.md`.
4. Keep the plugin header, `readme.txt`, package metadata, and Composer metadata synchronized.
5. Keep only the current release entry in the `readme.txt` changelog and retain the full history in `CHANGELOG.md`.
6. Run the complete local verification:

    ```bash
    composer install
    npm ci
    composer check
    npm run format:check
    npm run test:integration:ci
    npm run build:zip
    EXPECTED_VERSION="${RELEASE_VERSION}" npm run artifact:verify
    npm run artifact:test
    ```

7. Create a commit and a bare semantic-version tag matching `${RELEASE_VERSION}`.
8. Push the commit and tag only after review.
9. Publish a GitHub Release for that tag.

## Validate the protected deployment

1. Open the **Release** workflow in GitHub Actions.
2. Enter the bare release version.
3. Run with `dry_run` set to `true`.
4. Wait for the read-only verification job to pass.
5. Download and review the `charter-release-<version>` workflow artifact, including its checksum.
6. Approve the protected `wordpress.org` environment for the dry-run deployment job.
7. Review the Subversion dry-run output.

The verification job rebuilds from the release tag, verifies metadata, quality, integration behavior, activation, Plugin Check, and the ZIP, then saves that exact ZIP for the protected deployment job.

## Deploy to WordPress.org

1. Confirm that the `wordpress.org` GitHub environment requires an approver.
2. Confirm that `SVN_USERNAME` and the WordPress.org SVN-specific `SVN_PASSWORD` are stored only in that environment.
3. Run the **Release** workflow again with `dry_run` set to `false`.
4. Wait for verification to pass, then review the exact saved ZIP and checksum.
5. Approve the protected deployment job.
6. Confirm the release when WordPress.org sends the plugin-committer email.
7. Verify the public WordPress.org page, downloaded ZIP, Stable Tag, and assets.

The protected job verifies the transferred checksum, uploads `charter.zip` and its checksum to the existing GitHub Release, and only then deploys the ZIP's extracted directory to WordPress.org. Do not deploy source-tree files directly.
