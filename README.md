Changelog Check
===============

This GitHub app checks if a push or a pull request contains self-describing
changelog.  A log needs to be written in a changelog file.


Changelog file
--------------

A changelog file is automatically detected by its filename.  If a filename
looks like *CHANGES* or *ChangeLog*, no matter its case or file extension,
it is treated as a changelog file.


Skipping check
--------------

Sometimes a commit or a pull request has only a trivial change.  To skip
changelog check, add `[changelog skip]` (or `[skip changelog]`) to a commit
message.  It does not necessarily have to be the first line.

In case of a pull request, a skip mark works for any commit in the pull request.

FYI the syntax follows the convention of `[ci skip]`.


Source code
-----------

This app is distributed under [AGPL 3] or later.  See the source repository:

<https://github.com/planetarium/changelog-check>

[AGPL 3]: https://www.gnu.org/licenses/agpl-3.0.html
