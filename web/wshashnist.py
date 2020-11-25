#! /usr/bin/env python
import flask
import rq
import redis
import traceback

# Propios...
import settings
import tasks


app = flask.Flask(__name__)

redis_conn = redis.from_url( settings.REDIS_URL )

task_queue = rq.Queue( name            = settings.RQ_QUEUE_NAME,
                       connection      = redis_conn,
                       default_timeout = settings.RQ_JOB_TIMEOUT )


################################################################################

@app.errorhandler( 403 )
def handle_notfound( e ):

    resp = flask.jsonify( { 'error': 'Need a Json query' } )

    return flask.make_response( resp, 403 )

@app.errorhandler( 404 )
def handle_notfound( e ):

    resp = flask.jsonify( { 'error': 'Json field hashes not found' } )

    return flask.make_response( resp, 404 )

################################################################################

def get_hash_list():

    json_req = flask.request.get_json( silent=False )

    if json_req is None:

        flask.abort( 403 )

    hash_list = json_req.get( 'hashes', [] )

    if not len( hash_list ):

        flask.abort( 404 )

    return hash_list

################################################################################

def execute_sync( hash_list ):

    try:

        ret_dict = tasks.analyze( hash_list )

    except:

        ret_dict = { 'status':'FAILED' }

        print("EXCEPTION!! %s" % traceback.format_exc() )

    return ret_dict

################################################################################

def execute_async( hash_list ):

    job = task_queue.enqueue( tasks.analyze,
                              args        = ( hash_list, ),
                              result_ttl  = settings.RQ_RESULT_TTL,
                              failure_ttl = settings.RQ_FAILURE_TTL )

    return { 'status' : 'PENDING', 'analysis_id' : job.get_id() }

################################################################################

@app.route('/analyze', methods=['POST'])
def analyze():

    hash_list = get_hash_list()

    if len( hash_list ) >= settings.MINIMAL_ASYNC_ITEMS:

        ret_dict = execute_async( hash_list )

    else:

        ret_dict = execute_sync( hash_list )

    return flask.jsonify( ret_dict )

################################################################################

@app.route("/results/<analysis_id>", methods=['GET'])
def get_results( analysis_id ):

    job = task_queue.fetch_job( analysis_id )

    if job is None:

        return flask.jsonify( { 'status' : 'NONEXISTANT',
                                'analysis_id' : analysis_id } )

    if job.is_failed:

        # job.delete()

        return flask.jsonify( { 'status' : 'FAILED',
                                'analysis_id' : analysis_id } )

    if job.is_finished:

        result = job.result

        job.delete()

        return flask.jsonify( result )

    return flask.jsonify( { 'status' : 'PENDING',
                            'analysis_id' : analysis_id } )


###############################################################################
#
#
#
###############################################################################


if __name__ == '__main__':

    app.run( port=5000, debug=True )
