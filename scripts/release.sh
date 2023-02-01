#!/usr/bin/env bash
#set -x
set -e
scriptDir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd ${scriptDir}/..

python3 -c "import semantic_version" > /dev/null 2>&1 || {
    echo -e "Python library semantic_version is required.\nPlease install it using:\n\tpip install semantic_version" >&2
    exit 1
}


dryRun=false
version=
PUSH_URL=
force=false
while getopts ":dv:p:" opt; do
  case $opt in
    v)
      version=${OPTARG}
      ;;
    d)
      dryRun=true
      ;;
    f)
      force=true
      ;;
    p)
      PUSH_URL=${OPTARG}
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

if [[ -z "${version}" ]]; then
    echo "Parameter -v is required to indicate the version to build and tag" >&2
    exit 1
fi

if [[ "$(python3 -c "import semantic_version; print(semantic_version.validate('${version}'))" )" != "True" ]]; then
    echo "Parameter -v should be a semver 2.0 compatible version (http://semver.org/)" >&2
    exit 1
fi

update_types () {
    # $1 is new types version
    find . -type f \( -name 'types.yml' -o -name 'types.yaml' \) -exec sed -i -e "s/template_version: .*$/template_version: ${1}/g" {} \;
    git add */types.y*ml
}

check_snapshots_in_types () {
    has_snapshots=$(find . -type f \( -name 'types.yml' -o -name 'types.yaml' \) -exec grep -c -E "^  - .*:.*-SNAPSHOT" {} \;)
    if  [[ $(( ${has_snapshots//$'\n'/+} )) -ne 0 ]] ; then
        echo "Your TOSCA types definitions contain imports that reference SNAPSHOT versions..."
        if [ "${dryRun}" = false ] ; then
            read -p "Proceed anyway?" -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]] ; then
                exit 1
            fi
        fi
    fi
}

# read version
read -r major minor patch prerelease build <<< $(python3 -c "import semantic_version; v = semantic_version.Version('${version}'); print(v.major, v.minor, v.patch, '.'.join(v.prerelease), '.'.join(v.build));")

# Detect correct supporting branch
branch=$(git branch --list -r "*/release/${major}.${minor}")
if [[ -z "${branch}" ]]; then
    branch="main"
fi
branch=$(echo ${branch} | sed -e "s@^.*/\(release/.*\)@\1@")
echo "Switching to branch ${branch}..."
releaseBranch=${branch}
git checkout ${branch}

# Check branch tags
branchTag=$(git describe --abbrev=0 --tags ${branch}) || {
    branchTag="v0.0.0"
}
branchTag=$(echo $branchTag | sed -e 's/^v\(.*\)$/\1/')

if [[ "True" != "$(python3 -c "import semantic_version; print(semantic_version.Version('${version}') > semantic_version.Version('${branchTag}'))" )" ]]; then
    echo "Can't release version ${version} on top of branch ${branch} as it contains a newer tag: ${branchTag}" >&2
    exit 1
fi

if [[ "main" == "${branch}" ]] && [[ -z "${prerelease}" ]]; then
    # create release branch
    releaseBranch="release/${major}.${minor}"
    git checkout -b "${releaseBranch}"
fi

# Update current version
update_types "${version}"

check_snapshots_in_types

git commit -m "Prepare release ${version}"


git tag -a v${version} -m "Release tag v${version}"

# Update version
nextDevelopmentVersion=""
if [[ -z "${prerelease}" ]]; then
    # We are releasing a final version
    nextDevelopmentVersion=$(python3 -c "import semantic_version; v=semantic_version.Version('${version}'); print(v.next_patch())" )
    nextDevelopmentVersion="${nextDevelopmentVersion}-SNAPSHOT"
else
    # in prerelease revert to version minus prerelease plus -SNAPSHOT
    nextDevelopmentVersion="${major}.${minor}.${patch}-SNAPSHOT"
fi

update_types "${nextDevelopmentVersion}"

git commit -m "Prepare for next development cycle ${nextDevelopmentVersion}"

if [[ "main" == "${branch}" ]] && [[ -z "${prerelease}" ]]; then
    # merge back to main
    git checkout main
    # Update version
    nextDevelopmentVersion=$(python3 -c "import semantic_version; v=semantic_version.Version('${version}'); print(v.next_minor())" )
    nextDevelopmentVersion="${nextDevelopmentVersion}-SNAPSHOT"

    update_types "${nextDevelopmentVersion}"

    git commit -m "Prepare for next development cycle ${nextDevelopmentVersion}"

fi

# Push changes
if [ "${dryRun}" = false ] ; then
    set +x
    git push ${PUSH_URL} --all
    git push ${PUSH_URL} --tags
fi