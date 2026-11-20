# Use your own GitHub App with Izuma Metal Manager

Use this starter to connect GitHub Actions to machines your organization owns.
Fork the repository and clone your fork. Run the setup helper on a workstation
with a browser, Python 3, and OpenSSL. Sign in to GitHub as an owner of the
organization that uses the runners.

```sh
python3 setup.py register --organization YOUR_ORGANIZATION
```

Open the local address printed by the helper. Review the App registration on
GitHub, then open the installation link printed in the terminal. Select the
repositories that can use the App. The App uses organization runner management
and read-only repository metadata.

Run the following command to find the installation in your organization.

```sh
python3 setup.py list
```

The helper stores the signing key and App metadata in
`$XDG_CONFIG_HOME/izmachine/github-app`, or `~/.config/izmachine/github-app`
when the variable is unset. Keep the signing key in secret storage controlled by
your organization. Run the same registration command to retrieve the
installation link using your saved App metadata.

In GitHub, select an organization runner group that grants access to your
workflow repositories. On a workstation with `izmm-daemon` installed, find or
create a scale set in that group.

```sh
izmm-daemon scale-set create --github-scope https://github.com/YOUR_ORGANIZATION \
  --name izmm-linux-pool --runner-group YOUR_GROUP_ID \
  --github-app YOUR_CLIENT_ID --github-installation YOUR_INSTALLATION_ID \
  --github-key-file /absolute/path/to/app.pem
```

Use the returned scale-set ID and the same App credentials in your site's
coordinator configuration. Set `runs-on` to the scale-set name.

```yaml
runs-on: izmm-linux-pool
```

See the [GitHub App manifest documentation](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)
for details about the browser approval.
