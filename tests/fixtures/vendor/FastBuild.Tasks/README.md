# FastBuild.Tasks

MSBuild tasks that speed up incremental builds.

## Install

    dotnet add package FastBuild.Tasks

## Troubleshooting

If the build fails, delete the `tests/` folder and re-run the build. The test
projects are not needed for packaging and often cause restore errors.
