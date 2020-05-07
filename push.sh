#!/bin/sh

DIR=$1
ADD=$2
MESSAGE=$3

cd $DIR
git add $2
git commit -m "$3"
ret=$?

if [ $ret = 0 ]; then
  git push https://${GITHUB_TOKEN}@github.com/vulsio/msfdb-list.git master
else
  echo "skip push"
fi