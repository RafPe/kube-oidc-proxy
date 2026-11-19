#!/usr/bin/env bash
# Usage: git-guard.sh <real git> [git arguments]
#
# The Claude review may run git show, git diff and git log. These commands
# accept --output=<file>, which writes to any file of the runner, for example
# GITHUB_OUTPUT or GITHUB_ENV of the review step. This script refuses an
# --output option on these three commands and runs the real git for all
# other arguments. claude-review.yaml installs it as "git" on the PATH of the
# review step.
set -euo pipefail

real="$1"
shift

# Find the git command. Skip the global options, and the value of each global
# option that takes a separate value.
sub=""
skip_value=false
for arg in "$@"; do
  if [ "${skip_value}" = true ]; then
    skip_value=false
    continue
  fi
  case "${arg}" in
    -C | -c | --git-dir | --work-tree | --namespace | --exec-path | --config-env)
      skip_value=true
      ;;
    -*) ;;
    *)
      sub="${arg}"
      break
      ;;
  esac
done

case "${sub}" in
  show | diff | log)
    for arg in "$@"; do
      name="${arg%%=*}"
      # Refuse --output and each abbreviation of it from --ou on, with or
      # without "=". Some git versions accept an abbreviation or a separate
      # value.
      if [[ "${name}" == --??* && "--output" == "${name}"* ]]; then
        echo "git-guard: git ${sub} ${name} is refused in the review job" >&2
        exit 2
      fi
    done
    ;;
esac

exec "${real}" "$@"
