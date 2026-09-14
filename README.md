# VTS Hub

The [VTS Hub](https://hub.vts.edu) is hosted by Ironistic.

## Contacts

- Natthaphon Foithong <nfoithong@vts.edu> — Main Point of Contact
- Nicky Burridge <nburridge@vts.edu>
- Iron Quality <iq@ironistic.com> — Main Ironistic contact
- Chris Foss <chris@ironistic.com> — Co-Founder
- Justin Trevorrow <jtrevorrow@ironistic.com> — Technical Contact

---

## Deployment Workflow

Use a simple two-branch workflow with pull requests:

1. Create or update feature work from `Development`.
2. Open a pull request to merge changes into `Development`.
3. Review, test, and approve the pull request in `Development`.
4. When the development branch is ready for production, open a pull request from `Development` into `Main`.
5. Merge the `Development` → `Main` pull request to deploy the production release.

### Branch Rules

- `Development`: active integration branch for new work and validation
- `Main`: production branch, used for the live site release

This keeps changes reviewable and ensures production deployments happen only after approval through a pull request.

## Additional Information

- [Initial README](setup-init.md)
