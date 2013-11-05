-module(snarl_org_vnode).
-behaviour(riak_core_vnode).
-include("snarl.hrl").
-include_lib("riak_core/include/riak_core_vnode.hrl").


-export([start_vnode/1,
         init/1,
         terminate/2,
         handle_command/3,
         is_empty/1,
         delete/1,
         handle_handoff_command/3,
         handoff_starting/2,
         handoff_cancelled/1,
         handoff_finished/2,
         handle_handoff_data/2,
         encode_handoff_item/2,
         handle_coverage/4,
         handle_exit/3]).

%% Reads
-export([get/3]).

%% Writes
-export([
         add/4,
         set/4,
         import/4,
         delete/3,
         add_trigger/4, remove_trigger/4,
         repair/4
        ]).

-ignore_xref([
              start_vnode/1,
              get/3,
              add/4,
              delete/3,
              add_trigger/4, remove_trigger/4,
              set/4,
              import/4,
              repair/4
             ]).


-record(state, {db, partition, node}).

-define(MASTER, snarl_org_vnode_master).

%%%===================================================================
%%% API
%%%===================================================================

start_vnode(I) ->
    riak_core_vnode_master:get_vnode_pid(I, ?MODULE).

repair(IdxNode, Org, VClock, Obj) ->
    riak_core_vnode_master:command(IdxNode,
                                   {repair, Org, VClock, Obj},
                                   ignore,
                                   ?MASTER).

%%%===================================================================
%%% API - reads
%%%===================================================================

get(Preflist, ReqID, Org) ->
    riak_core_vnode_master:command(Preflist,
                                   {get, ReqID, Org},
                                   {fsm, undefined, self()},
                                   ?MASTER).

%%%===================================================================
%%% API - writes
%%%===================================================================

set(Preflist, ReqID, UUID, Attributes) ->
    riak_core_vnode_master:command(Preflist,
                                   {set, ReqID, UUID, Attributes},
                                   {fsm, undefined, self()},
                                   ?MASTER).

import(Preflist, ReqID, UUID, Import) ->
    riak_core_vnode_master:command(Preflist,
                                   {import, ReqID, UUID, Import},
                                   {fsm, undefined, self()},
                                   ?MASTER).

add(Preflist, ReqID, UUID, Org) ->
    riak_core_vnode_master:command(Preflist,
                                   {add, ReqID, UUID, Org},
                                   {fsm, undefined, self()},
                                   ?MASTER).

delete(Preflist, ReqID, Org) ->
    riak_core_vnode_master:command(Preflist,
                                   {delete, ReqID, Org},
                                   {fsm, undefined, self()},
                                   ?MASTER).

add_trigger(Preflist, ReqID, Org, Val) ->
    riak_core_vnode_master:command(Preflist,
                                   {add_trigger, ReqID, Org, Val},
                                   {fsm, undefined, self()},
                                   ?MASTER).

remove_trigger(Preflist, ReqID, Org, Val) ->
    riak_core_vnode_master:command(Preflist,
                                   {remove_trigger, ReqID, Org, Val},
                                   {fsm, undefined, self()},
                                   ?MASTER).
%%%===================================================================
%%% VNode
%%%===================================================================
init([Partition]) ->
    DB = list_to_atom(integer_to_list(Partition)),
    fifo_db:start(DB),
    {ok, #state {
            db = DB,
            node = node(),
            partition = Partition}}.

%% Sample command: respond to a ping
handle_command(ping, _Sender, State) ->
    {reply, {pong, State#state.partition}, State};

handle_command({repair, Org, _VClock, #snarl_obj{} = Obj},
               _Sender, State) ->
    case fifo_db:get(State#state.db, <<"org">>, Org) of
        {ok, _O} when _O#snarl_obj.vclock =:= _VClock ->
            fifo_db:put(State#state.db, <<"org">>, Org, Obj);
        not_found ->
            fifo_db:put(State#state.db, <<"org">>, Org, Obj);
        _ ->
            lager:warning("[ORG:~s] Could not read repair, org changed.", [Org])
    end,
    {noreply, State};

handle_command({get, ReqID, Org}, _Sender, State) ->
    Res = case fifo_db:get(State#state.db, <<"org">>, Org) of
              {ok, #snarl_obj{val = V0} = R} ->
                  R#snarl_obj{val = snarl_org_state:load(V0)};
              not_found ->
                  not_found
          end,
    NodeIdx = {State#state.partition, State#state.node},
    {reply, {ok, ReqID, NodeIdx, Res}, State};

handle_command({add, {ReqID, Coordinator} = ID, UUID, Org}, _Sender, State) ->
    Org0 = snarl_org_state:new(),
    Org1 = snarl_org_state:name(ID, Org, Org0),
    Org2 = snarl_org_state:uuid(ID, UUID, Org1),
    VC0 = vclock:fresh(),
    VC = vclock:increment(Coordinator, VC0),
    OrgObj = #snarl_obj{val=Org2, vclock=VC},
    fifo_db:put(State#state.db, <<"org">>, UUID, OrgObj),
    {reply, {ok, ReqID}, State};

handle_command({delete, {ReqID, _Coordinator}, Org}, _Sender, State) ->
    fifo_db:delete(State#state.db, <<"org">>, Org),
    {reply, {ok, ReqID}, State};

handle_command({set, {ReqID, Coordinator}, Org, Attributes}, _Sender, State) ->
    case fifo_db:get(State#state.db, <<"org">>, Org) of
        {ok, #snarl_obj{val=H0} = O} ->
            H1 = snarl_org_state:load(H0),
            H2 = lists:foldr(
                   fun ({Attribute, Value}, H) ->
                           snarl_org_state:set_metadata(Coordinator,
                                                        Attribute, Value, H)
                   end, H1, Attributes),
            fifo_db:put(State#state.db, <<"org">>, Org,
                        snarl_obj:update(H2, Coordinator, O)),
            {reply, {ok, ReqID}, State};
        R ->
            lager:error("[orgs] tried to write to a non existing org: ~p", [R]),
            {reply, {ok, ReqID, not_found}, State}
    end;

handle_command({import, {ReqID, Coordinator} = ID, UUID, Data}, _Sender, State) ->
    H1 = snarl_org_state:load(Data),
    H2 = snarl_org_state:uuid(ID, UUID, H1),
    case fifo_db:get(State#state.db, <<"org">>, UUID) of
        {ok, O} ->
            fifo_db:put(State#state.db, <<"org">>, UUID,
                        snarl_obj:update(H2, Coordinator, O)),
            {reply, {ok, ReqID}, State};
        _R ->
            VC0 = vclock:fresh(),
            VC = vclock:increment(Coordinator, VC0),
            OrgObj = #snarl_obj{val=H2, vclock=VC},
            fifo_db:put(State#state.db, <<"org">>, UUID, OrgObj),
            {reply, {ok, ReqID}, State}
    end;

handle_command({Action, {ReqID, Coordinator}, Org, Param1, Param2}, _Sender, State) ->
    change_org(Org, Action, [Param1, Param2], Coordinator, State, ReqID);

handle_command({Action, {ReqID, Coordinator}, Org, Param1}, _Sender, State) ->
    change_org(Org, Action, [Param1], Coordinator, State, ReqID);

handle_command(Message, _Sender, State) ->
    lager:error("[org] Unknown message: ~p", [Message]),
    {noreply, State}.

handle_handoff_command(?FOLD_REQ{foldfun=Fun, acc0=Acc0}, _Sender, State) ->
    Acc = fifo_db:fold(State#state.db, <<"org">>, Fun, Acc0),
    {reply, Acc, State};

handle_handoff_command({get, _ReqID, _Vm} = Req, Sender, State) ->
    handle_command(Req, Sender, State);

handle_handoff_command(Req, Sender, State) ->
    S1 = case handle_command(Req, Sender, State) of
             {noreply, NewState} ->
                 NewState;
             {reply, _, NewState} ->
                 NewState
         end,
    {forward, S1}.

handoff_starting(TargetNode, State) ->
    lager:warning("Starting handof to: ~p", [TargetNode]),
    {true, State}.

handoff_cancelled(State) ->
    {ok, State}.

handoff_finished(_TargetNode, State) ->
    {ok, State}.

handle_handoff_data(Data, State) ->
    {Org, #snarl_obj{val = Vin} = Obj} = binary_to_term(Data),
    V = snarl_org_state:load(Vin),
    case fifo_db:get(State#state.db, <<"org">>, Org) of
        {ok, #snarl_obj{val = V0}} ->
            V1 = snarl_org_state:load(V0),
            fifo_db:put(State#state.db, <<"org">>, Org,
                        Obj#snarl_obj{val = snarl_org_state:merge(V, V1)});
        not_found ->
            VC0 = vclock:fresh(),
            VC = vclock:increment(node(), VC0),
            OrgObj = #snarl_obj{val=V, vclock=VC},
            fifo_db:put(State#state.db, <<"org">>, Org, OrgObj)
    end,
    {reply, ok, State}.

encode_handoff_item(Org, Data) ->
    term_to_binary({Org, Data}).

is_empty(State) ->
    fifo_db:fold(State#state.db,
                 <<"org">>,
                 fun (_,_, _) ->
                         {false, State}
                 end, {true, State}).

delete(State) ->
    Trans = fifo_db:fold(State#state.db,
                         <<"org">>,
                         fun (K,_, A) ->
                                 [{delete, <<"org", K/binary>>} | A]
                         end, []),
    fifo_db:transact(State#state.db, Trans),
    {ok, State}.

handle_coverage({lookup, Name}, _KeySpaces, {_, ReqID, _}, State) ->
    Res = fifo_db:fold(State#state.db,
                       <<"org">>,
                       fun (UUID, #snarl_obj{val=G0}, not_found) ->
                               G1 = snarl_org_state:load(G0),
                               case snarl_org_state:name(G1) of
                                   Name ->
                                       UUID;
                                   _ ->
                                       not_found
                               end;
                           (_U, _, Res) ->
                               Res
                       end, not_found),
    {reply,
     {ok, ReqID, {State#state.partition, State#state.node}, [Res]},
     State};

handle_coverage(list, _KeySpaces, {_, ReqID, _}, State) ->
    List = fifo_db:fold(State#state.db,
                        <<"org">>,
                        fun (K, _, L) ->
                                [K|L]
                        end, []),
    {reply,
     {ok, ReqID, {State#state.partition,State#state.node}, List},
     State};

handle_coverage({list, Requirements}, _KeySpaces, {_, ReqID, _}, State) ->
    Getter = fun(#snarl_obj{val=S0}, <<"uuid">>) ->
                     snarl_org_state:uuid(snarl_org_state:load(S0))
             end,
    List = fifo_db:fold(State#state.db,
                        <<"org">>,
                        fun (Key, E, C) ->
                                case rankmatcher:match(E, Getter, Requirements) of
                                    false ->
                                        C;
                                    Pts ->
                                        [{Pts, Key} | C]
                                end
                        end, []),
    {reply,
     {ok, ReqID, {State#state.partition, State#state.node}, List},
     State};

handle_coverage(_Req, _KeySpaces, _Sender, State) ->
    {stop, not_implemented, State}.

handle_exit(_Pid, _Reason, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

change_org(Org, Action, Vals, Coordinator, State, ReqID) ->
    case fifo_db:get(State#state.db, <<"org">>, Org) of
        {ok, #snarl_obj{val=H0} = O} ->
            H1 = snarl_org_state:load(H0),
            ID = {ReqID, Coordinator},
            H2 = case Vals of
                     [Val] ->
                         snarl_org_state:Action(ID, Val, H1);
                     [Val1, Val2] ->
                         snarl_org_state:Action(ID, Val1, Val2, H1)
                 end,
            fifo_db:put(State#state.db, <<"org">>, Org,
                        snarl_obj:update(H2, Coordinator, O)),
            {reply, {ok, ReqID}, State};
        R ->
            lager:error("[orgs] tried to write to a non existing org: ~p", [R]),
            {reply, {ok, ReqID, not_found}, State}
    end.