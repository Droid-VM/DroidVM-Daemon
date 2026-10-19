sync
if [ -n "$FAILED_ACTIONS" ]; then
    marker "RESULT:PARTIAL:$FAILED_ACTIONS"
else
    marker RESULT:OK
fi
