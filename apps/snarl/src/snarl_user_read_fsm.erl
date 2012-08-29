%% @doc The coordinator for stat get operations.  The key here is to
%% generate the preflist just like in wrtie_fsm and then query each
%% replica and wait until a quorum is met.
-module(snarl_user_read_fsm).
-behavior(gen_fsm).
-include("snarl.hrl").

%% API
-export([start_link/5, get/1, list/0, auth/2]).


-export([reconcile/1, different/1, needs_repair/2, repair/3, unique/1]).

%% Callbacks
-export([init/1, code_change/4, handle_event/3, handle_info/3,
         handle_sync_event/4, terminate/3]).

%% States
-export([prepare/2, execute/2, waiting/2, wait_for_n/2, finalize/2]).

-record(state, {req_id,
                from,
		user,
		op,
		r=?R,
                preflist,
                num_r=0,
		ch,
		timeout=?DEFAULT_TIMEOUT,
		val,
                replies=[]}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Op, ReqID, From, User, Val) ->
    gen_fsm:start_link(?MODULE, [Op, ReqID, From, User, Val], []).

auth(User, Passwd) ->
    ReqID = mk_reqid(),
    snarl_user_read_fsm_sup:start_read_fsm([auth, ReqID, self(), User, Passwd]),
    {ok, ReqID}.

get(User) ->
    ReqID = mk_reqid(),
    snarl_user_read_fsm_sup:start_read_fsm([get, ReqID, self(), User, undefined]),
    {ok, ReqID}.

list() ->
    ReqID = mk_reqid(),
    snarl_user_read_fsm_sup:start_read_fsm([list, ReqID, self(), undefined, undefined]),
    {ok, ReqID}.

%%%===================================================================
%%% States
%%%===================================================================

%% Intiailize state data.
init([Op, ReqId, From, User, Val]) ->
    ?PRINT({init, [Op, ReqId, From, User, Val]}),
    SD = #state{req_id=ReqId,
                from=From,
		op=Op,
		val=Val,
                user=User},
    {ok, prepare, SD, 0};

init([Op, ReqId, From, User]) ->
    ?PRINT({init, [Op, ReqId, From, User]}),
    SD = #state{req_id=ReqId,
                from=From,
		op=Op,
                user=User},
    {ok, prepare, SD, 0};

init([Op, ReqId, From]) ->
    ?PRINT({init, [Op, ReqId, From]}),
    SD = #state{req_id=ReqId,
                from=From,
		op=Op},
    {ok, prepare, SD, 0}.

%% @doc Calculate the Preflist.
prepare(timeout, SD0=#state{user=User, op=Op,
			   req_id=ReqId}) ->
    SD = case Op of
	     list ->
		 PVC = ?N,
		 {Nodes, _Other} = 
		     riak_core_coverage_plan:create_plan(
		       all, ?N, PVC, ReqId, snarl_user),
		 {ok, CHash} = riak_core_ring_manager:get_my_ring(),
		 {_, CH} = riak_core_ring:chash(CHash),
		 SD0#state{preflist=Nodes, ch=CH};
	     _ ->
		 DocIdx = riak_core_util:chash_key({<<"user">>, term_to_binary(User)}),
		 Prelist = riak_core_apl:get_apl(DocIdx, ?N, snarl_user),
		 SD0#state{preflist=Prelist}
	 end,
    {next_state, execute, SD, 0}.

%% @doc Execute the get reqs.
execute(timeout, SD0=#state{req_id=ReqId,
                            user=User,
			    op=Op,
			    val=Val,
                            preflist=Prelist}) ->
    ?PRINT({execute, User, Val}),
    case User of
	undefined ->
	    snarl_user_vnode:Op(Prelist, ReqId);
	_ ->
	    case Val of
		undefined ->
		    snarl_user_vnode:Op(Prelist, ReqId, User);
		_ ->
		    
		    snarl_user_vnode:Op(Prelist, ReqId, User, Val)
	    end
    end,
    {next_state, waiting, SD0}.

%% @doc Wait for R replies and then respond to From (original client
%% that called `snarl:get/2').
%% TODO: read repair...or another blog post?


waiting({{undefined,{Partition, _Node} = IdxNode},
	 {ok,ReqID,IdxNode,Obj}},
	SD0=#state{from=From, replies=Replies0, r=R, ch=Ch}) ->
    Idx = ch_index(Partition, Ch),
    Group = Idx div ?N,
    Replies1 = case Replies0 of
		   [] ->
		       dict:new();
		   _ ->
		       Replies0
	       end,
    Replies = dict:update(Group,
			  fun(PartReplies) ->
				  [{IdxNode, Obj} | PartReplies]
			  end, [{IdxNode, Obj}], Replies1),
    NumR = dict:fold(fun(_, Rs, AccIn) ->
			     case length(Rs) of
				 L when L < AccIn ->
				     L;
				 L when AccIn == 0 ->
				     L;
				 _  ->
				     AccIn
			     end
		     end, 0, Replies),
    KeyCount = length(dict:fetch_keys(Replies1)),
    ExpectedCount = length(Ch) div ?N,
    SD = SD0#state{num_r=NumR,replies=Replies},
    if
        NumR =:= R 
	andalso
	KeyCount =:= ExpectedCount ->
	    MergedReplies = dict:map(fun(_, Rs) ->
					     merge(Rs)
				     end, Replies),
	    ReplyList = dict:fold(fun(_, Merged, AccIn) ->
					  Rs = snarl_obj:val(Merged),
					  statebox:value(Rs) ++ AccIn
				  end, [], MergedReplies),
	    ?PRINT(finished),
	    From ! {ReqID, ok, ReplyList},
	    {stop, normal, SD};
        true -> 
	    {next_state, waiting, SD}
    end;

waiting({ok, ReqID, IdxNode, Obj},
        SD0=#state{from=From, num_r=NumR0, replies=Replies0,
                   r=R, timeout=Timeout}) ->
    NumR = NumR0 + 1,
    Replies = [{IdxNode, Obj}|Replies0],
    SD = SD0#state{num_r=NumR,replies=Replies},
    if
        NumR =:= R ->
	    case merge(Replies) of
		not_found ->
		    From ! {ReqID, ok, not_found};
		Merged ->
		    Reply = snarl_obj:val(Merged),
		    From ! {ReqID, ok, statebox:value(Reply)}
	    end,
	    if 
		NumR =:= ?N -> 
		    {next_state, finalize, SD, 0};
	       true -> 
		    {next_state, wait_for_n, SD, Timeout}
	    end;
        true -> 
	    {next_state, waiting, SD}
    end.

wait_for_n({ok, _ReqID, IdxNode, Obj},
             SD0=#state{num_r=?N - 1, replies=Replies0}) ->
    Replies = [{IdxNode, Obj}|Replies0],
    {next_state, finalize, SD0#state{num_r=?N, replies=Replies}, 0};

wait_for_n({ok, _ReqID, IdxNode, Obj},
             SD0=#state{num_r=NumR0, replies=Replies0, timeout=Timeout}) ->
    NumR = NumR0 + 1,
    Replies = [{IdxNode, Obj}|Replies0],
    {next_state, wait_for_n, SD0#state{num_r=NumR, replies=Replies}, Timeout};

%% TODO partial repair?
wait_for_n(timeout, SD) ->
    {stop, timeout, SD}.

finalize(timeout, SD=#state{op=Op, replies=Replies, user=User}) ->
    case Op of
	list ->
	    {stop, normal, SD};
	_ ->
	    MObj = merge(Replies),
	    case needs_repair(MObj, Replies) of
		true ->
		    repair(User, MObj, Replies),
		    {stop, normal, SD};
		false ->
		    {stop, normal, SD}
	    end
    end.

handle_info(_Info, _StateName, StateData) ->
    {stop,badmsg,StateData}.

handle_event(_Event, _StateName, StateData) ->
    {stop,badmsg,StateData}.

handle_sync_event(_Event, _From, _StateName, StateData) ->
    {stop,badmsg,StateData}.

code_change(_OldVsn, StateName, State, _Extra) -> {ok, StateName, State}.

terminate(_Reason, _SN, _SD) ->
    ok.

%%%===================================================================
%%% Internal Functions
%%%===================================================================

mk_reqid() -> erlang:phash2(erlang:now()).


%% @pure
%%
%% @doc Given a list of `Replies' return the merged value.
-spec merge([vnode_reply()]) -> snarl_obj() | not_found.
merge(Replies) ->
    Objs = [Obj || {_,Obj} <- Replies],
    snarl_obj:merge(snarl_user_read_fsm, Objs).

%% @pure
%%
%% @doc Reconcile conflicts among conflicting values.
-spec reconcile([A :: statebox:statebox()]) -> A :: statebox:statebox().

reconcile(Vals) -> 
    statebox:merge(Vals).


%% @pure
%%
%% @doc Given the merged object `MObj' and a list of `Replies'
%% determine if repair is needed.
-spec needs_repair(any(), [vnode_reply()]) -> boolean().
needs_repair(MObj, Replies) ->
    Objs = [Obj || {_,Obj} <- Replies],
    lists:any(different(MObj), Objs).

%% @pure
different(A) -> fun(B) -> not snarl_obj:equal(A,B) end.

%% @impure
%%
%% @doc Repair any vnodes that do not have the correct object.
-spec repair(string(), snarl_obj(), [vnode_reply()]) -> io.
repair(_, _, []) -> io;

repair(StatName, MObj, [{IdxNode,Obj}|T]) ->
    case snarl_obj:equal(MObj, Obj) of
        true -> repair(StatName, MObj, T);
        false ->
            snarl_user_vnode:repair(IdxNode, StatName, MObj),
            repair(StatName, MObj, T)
    end.

%% pure
%%
%% @doc Given a list return the set of unique values.
-spec unique([A::any()]) -> [A::any()].
unique(L) ->
    sets:to_list(sets:from_list(L)).


ch_index(I, L) ->
    ch_index(I, L, 0).

ch_index(_I, [{_I, _}|_], N) ->
    N;

ch_index(I, [{_O, _}|R], N) ->
    ch_index(I, R, N+1);

ch_index(_I, [], _N) ->
    failed.
