class Variable(object):
    """
    negated = '!'? name = ('ARGS_COMBINED_SIZE' | 'AUTH_TYPE' | 'DURATION' | 'FILES_COMBINED_SIZE' | 'FULL_REQUEST_LENGTH' |
        'FILES_SIZES' | 'FILES_TMPNAMES' | 'FILES_TMP_CONTENT' | 'HIGHEST_SEVERITY' | 'INBOUND_DATA_ERROR' |
        'MATCHED_VAR_NAME' | 'MODSEC_BUILD' | 'MULTIPART_CRLF_LF_LINES' | 'MULTIPART_STRICT_ERROR' |
        'MULTIPART_UNMATCHED_BOUNDARY' | 'OUTBOUND_DATA_ERROR' | 'PATH_INFO' | 'PERF_ALL' | 'PERF_COMBINED' |
        'PERF_GC' | 'PERF_LOGGING' | 'PERF_PHASE1' | 'PERF_PHASE2' | 'PERF_PHASE3' | 'PERF_PHASE4' | 'PERF_PHASE5' |
        'PERF_SREAD' | 'PERF_SWRITE' | 'REMOTE_ADDR' | 'REMOTE_HOST' | 'REMOTE_PORT' | 'REMOTE_USER' |
        'REQBODY_ERROR' | 'REQBODY_ERROR_MSG' | 'REQBODY_PROCESSOR' | 'REQUEST_BODY_LENGTH' | 'RESPONSE_BODY' |
        'RESPONSE_CONTENT_LENGTH' | 'RESPONSE_CONTENT_TYPE' | 'RESPONSE_HEADERS' | 'RESPONSE_PROTOCOL' |
        'RESPONSE_STATUS' | 'RULE' | 'SCRIPT_BASENAME' | 'SCRIPT_FILENAME' | 'SCRIPT_GID' | 'SCRIPT_GROUPNAME' |
        'SCRIPT_MODE' | 'SCRIPT_UID' | 'SCRIPT_USERNAME' | 'SDBM_DELETE_ERROR' | 'SERVER_ADDR' | 'SERVER_NAME' |
        'SERVER_PORT' | 'SESSION' | 'SESSIONID' | 'STATUS_LINE' | 'STREAM_INPUT_BODY' | 'STREAM_OUTPUT_BODY' |
        'TIME' | 'TIME_DAY' | 'TIME_EPOCH' | 'TIME_HOUR' | 'TIME_MIN' | 'TIME_MON' | 'TIME_SEC' | 'TIME_WDAY' |
        'TIME_YEAR' | 'UNIQUE_ID' | 'URLENCODED_ERROR' | 'USERID' | 'USERAGENT_IP' | 'WEBAPPID' | 'WEBSERVER_ERROR_LOG' | 'MATCHED_VAR'
        count=Count? collection=CollectionName ':'? collectionArg=CollectionArgument?) | special=SpecialCollection ;
    """

    def __init__(self, parent, negated, name, collection):
        self.parent = parent
        self.negated = negated
        self.name = name
        self.collection = collection

    def __repr__(self):
        negated = ""
        name = ""
        collection = ""
        if self.negated:
            negated = "!"
        if self.name:
            name = "{name}".format(name=self.name)
        if self.collection:
            collection = self.collection

        repr = "{negated}{name}{collection}".format(
            negated=negated, name=name, collection=collection
        )
        return repr
