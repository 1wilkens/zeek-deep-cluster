@load base/frameworks/broker

module DeepCluster;

const DEBUG = T;

export {
    # SYSTEM CONFIG

    # Enable broker event forwarding
    redef Broker::forward_messages = T;

    # Check for unused event handler (that indicate a missspelled name for example)
    #redef check_for_unused_event_handlers = T;

    # TOPICS, PREFIXES AND SUFFIXES
    const topic_prefix = "zeek/deepcluster/" &redef;

    const node_topic_prefix = topic_prefix + "node/" &redef;
    const group_topic_prefix = topic_prefix + "group/" &redef;
    const parent_topic_prefix = topic_prefix + "parent/" &redef;

    const control_topic = topic_prefix + "control" &redef;

    const initial_delay = 5sec &redef;

    const subscribe_on_node_name = T &redef;

    # RECORDS

    ## Record type to indicate a node in a cluster.
    type Node: record {
        ## The name of the cluster node
        name:         string;
        ## The IP address of the cluster node.
        ip:           addr;
        ## If the *ip* field is a non-global IPv6 address, this field
        ## can specify a particular :rfc:`4007` ``zone_id``.
        zone_id:      string      &default="";
        ## The port that this node will listen on for peer connections.
        p:            port;
        ## Identifier for the interface a worker is sniffing.
        interface:    string      &optional;
        ## A unique identifier assigned to the node by the broker framework.
        ## This field is only set while a node is connected.
        id:           string      &optional;

        # Set of groups the node belongs to.
        # Defaults to empty set to simplify initialization
        groups:       set[string] &default=set();
        # Set of groups the node acts as a parent of.
        # Defaults to empty set to simplify initialization
        parent:       set[string] &default=set();
    };

    # VARIABLES
    const self: Node = [$name="", $ip=0.0.0.0, $p=9999/tcp] &redef;

    const peers: vector of Node = vector() &redef;

    # XXX: can_accomodate function

    # FUNCTIONS
    global is_enabled: function(): bool;

    global create_group: function(group: string);
    global join_group: function(group: string);
    global leave_group: function(group: string);

    global is_child_of_group: function(group: string): bool;
    global is_parent_of_group: function(group: string): bool;
    global is_parent_of_node: function(node_id: string, group: string): bool;

    global can_take_children: function(number: count): bool &redef;

    global topic_for_group: function(group: string): string;
    global parent_topic_for_group: function(group: string): string;

    global children_for_group: function(group: string): set[string];
}

# EVENTS
global setup_initial_groups: event(reschedule: bool &default=F);

global group_join_request: event(group: string, node_id: string, sender: string, last_group_node: string);

global group_join_confirm: event(group: string, parent_id: string);

global handover_request: event(group: string, node_ids: set[string]);

global handover_confirm: event(group: string, node_ids: set[string]);

global get_state: event();

global status: event(name: string, id: string, peer_ids: set[string], groups: set[string], children: set[string]);

# VARIABLES

global peer_ids: set[string] = set();

# Groups that the node participates in as a child
global child_groups: table[string] of string;

# Children that the node acts a a parent for
# [group] -> [last_node] -> set(nodes)
global children: table[string] of table[string] of set[string];

const zero_time = double_to_time(0.0);

# PRIVATE FUNCTIONS

function log(msg: string) {
    if (DEBUG) {
        print(msg);
        flush_all();
    }
}

function subscribe(topic: string) {
    log(fmt("[cluster/main] => Subscribing to %s", topic));
    Broker::subscribe(topic);
}

function unsubscribe(topic: string) {
    log(fmt("[cluster/main] => Unsubscribing to %s", topic));
    Broker::unsubscribe(topic);
}

function node_topic(name_or_id: string): string {
    # XXX: Strip process id suffix?
    return node_topic_prefix + name_or_id;
}

function parent_for_group(group: string): string {
    if (group !in child_groups) {
        # XXX: warn via Reporter?
        return "--INVALID--";
    }

    return node_topic(child_groups[group]);
}

function connect_initial_peers() {
    log(fmt("[cluster/main] Connecting to %d initial peer(s)", |peers|));
    for (i in peers) {
        local _peer = peers[i];
        local _res = Broker::peer(cat(_peer$ip), _peer$p);
        log(fmt("[cluster/main] => Peering to %s:%d aka '%s'", cat(_peer$ip), _peer$p, _peer$name));
    }
}

function peer_topics(sender: string): set[string] {
    local _peers = peer_ids - set(sender);
    local _topics: set[string] = set();
    for (_p in _peers) {
        add _topics[node_topic(_p)];
    }

    return _topics;
}

# PRIVATE EVENTS

event setup_initial_groups(reschedule: bool) {
    if (reschedule) {
        # Ignore first call to event handler and reschedule due to broken scheduling in zeek_init
        schedule initial_delay { DeepCluster::setup_initial_groups() };
        return;
    }

    log("[cluster/main] Setting up initial groups");
    for (_g in self$groups) {
        join_group(_g);
    }

    for (_g in self$parent) {
        create_group(_g);
    }
}

# PUBLIC API

function is_enabled(): bool {
    return (self$name != "");
}

function create_group(group: string) {
    log(fmt("[cluster/main] Creating group '%s'", group));
    subscribe(topic_for_group(group));
    subscribe(parent_topic_prefix + group);
    children[group] = table();
}

function join_group(group: string) {
    log(fmt("[cluster/main] Joining group '%s'", group));
    local _e = Broker::make_event(DeepCluster::group_join_request, group, self$id, self$id, self$id);
    for (_p in peer_ids) {
        log(fmt("[cluster/main] Publishing group_join_request to %s", node_topic(_p)));
        Broker::publish(node_topic(_p), _e);
    }
}

function leave_group(group: string) {
    log(fmt("[cluster/main] Leaving group '%s'", group));
    unsubscribe(topic_for_group(group));
    delete child_groups[group];
    if (group in children) {
        # XXX: Should we initiate a handover here?
        delete children[group];
        #unsubscribe(_parent_topic(group));
    }
}

function is_child_of_group(group: string): bool {
    return group in child_groups;
}

function is_parent_of_group(group: string): bool {
    return group in children;
}

function is_parent_of_node(node_id: string, group: string): bool {
    # XXX: Implement
    return node_id in children;
}

function can_take_children(number: count): bool {
    # XXX: Implement sensible default
    return T;
}

function topic_for_group(group: string): string {
    # XXX: sanitize group name?
    return group_topic_prefix + group;
}

function parent_topic_for_group(group: string): string {
    # XXX: Currently requires that you are child of the group as the parent is directly addressed
    return node_topic(parent_for_group(group));
    # XXX: sanitize group name?
    # XXX: Change to this, if broker supports topic guards
    #return topic_for_group(group) + parent_topic_suffix;
}

function children_for_group(group: string): set[string] {
    local _topics: set[string] = set();
    if (group in children) {
        for (_ln in children[group]) {
            for (_c in children[group][_ln]) {
                add _topics[node_topic(_c)];
            }
        }
    }
    return _topics;
}

event zeek_init() &priority=5 {
    log("[cluster/main] Begin zeek_init()");

    # Set our own id in the Node
    self$id = Broker::node_id();

    log(fmt("[cluster/main] Hi, I'm '%s' aka %s", self$name, self$id));

    # Listen on the global control topic
    subscribe(control_topic);
    # and our node node topics (by id and by name (if enabled))
    subscribe(node_topic(self$id));
    if (subscribe_on_node_name) {
        subscribe(node_topic(self$name));
    }

    # Also forward the global status topic XXX: Maybe revisit this
    Broker::forward(topic_prefix + "status");

    # Listen for incoming connections
    Broker::listen();

    # Setup initial state
    connect_initial_peers();
    # Work around broken scheduling in zeek_init
    # see: https://docs.zeek.org/en/latest/scripts/base/bif/event.bif.zeek.html#id-zeek_init
    local _reschedule = network_time() == zero_time;
    schedule initial_delay { DeepCluster::setup_initial_groups(_reschedule) };

    log("[cluster/main] Finished zeek_init()");
}

event Broker::peer_added(endpoint: Broker::EndpointInfo, _: string) {
    local _remote_id = endpoint$id;
    local _remote_ip = endpoint$network$address;
    #log(fmt("[cluster/main] Broker::peer_added: %s@%s", _remote_id, _remote_ip));

    add peer_ids[_remote_id];
}

event Broker::peer_removed(endpoint: Broker::EndpointInfo, _: string) {
    local _remote_id = endpoint$id;
    local _remote_ip = endpoint$network$address;
    #log(fmt("[cluster/main] Broker::peer_removed: %s@%s", _remote_id, _remote_ip));

    delete peer_ids[_remote_id];
}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, _: string) {
    local _remote_id = endpoint$id;
    local _remote_ip = endpoint$network$address;
    #log(fmt("[cluster/main] Broker::peer_lost: %s@%s", _remote_id, _remote_ip));

    delete peer_ids[_remote_id];
}

event DeepCluster::get_state() {
    log("[cluster/main] DeepCluster::get_state");
    local _groups: set[string] = set();
    for (_g in child_groups) {
        add _groups[_g];
    }
    for (_g in children) {
        add _groups[_g];
    }
    local _children: set[string] = set();
    for (_c in children) {
        add _children[_c];
    }

    local e = Broker::make_event(DeepCluster::status, self$name, self$id, peer_ids, _groups, _children);
    Broker::publish(topic_prefix + "status", e);
}

event DeepCluster::group_join_request(group: string, node_id: string, sender: string, last_group_node: string) {
    #log(fmt("[cluster/main] DeepCluster::group_join_request for group '%s', node_id=%s, sender=%s, last_group_node=%s", group, node_id, sender, last_group_node));
    local _topics: set[string] = set();

    if (group in children) {
        # We are parent for this group -> accept or reject new child
        if (can_take_children(1)) {
            # We can take in the child -> publish `group_join_confirm`
            log(fmt("[cluster/main] Accepting child for group '%s' (id=%s)", group, node_id));

            if (last_group_node !in children[group]) {
                children[group][last_group_node] = set();
            }
            add children[group][last_group_node][node_id];
            local gjc = Broker::make_event(DeepCluster::group_join_confirm, group, self$id);
            Broker::publish(node_topic(node_id), gjc);
        }
        else {
            # We cannot take in the child -> initiate `handover_request`
            log(fmt("[cluster/main] Initiating handover for group '%s' to %s", group, last_group_node));

            local _nodes: set[string] = set();
            if (group in children && last_group_node in children[group]) {
                _nodes = children[group][last_group_node];
            }
            add _nodes[node_id];
            local hr = Broker::make_event(DeepCluster::handover_request, group, _nodes);
            Broker::publish(node_topic(last_group_node), hr);
        }
    }
    else if (group in child_groups) {
        # We are child of this group -> update `last_group_node`
        local gjr = Broker::make_event(DeepCluster::group_join_request, group, node_id, self$id, self$id);
        _topics = peer_topics(sender);
        for (_t in _topics) {
            log(fmt("[cluster/main] Publishing updated group_join_request by %s for group '%s' to %s", node_id, group, _t));
            Broker::publish(_t, gjr);
        }
    }
    else {
        # We are not part of the group -> just pass the event further up
        local fwd = Broker::make_event(DeepCluster::group_join_request, group, node_id, self$id, last_group_node);
        _topics = peer_topics(sender);
        for (_t in _topics) {
            log(fmt("[cluster/main] Forwarding group_join_request by %s for group '%s' to %s", node_id, group, _t));
            Broker::publish(_t, fwd);
        }
    }
}

event DeepCluster::group_join_confirm(group: string, parent_id: string) {
    # XXX: possibly verify this?
    if (group !in child_groups) {
        log(fmt("[cluster/main] Got membership confirmation for group '%s' by parent '%s'", group, parent_id));
        child_groups[group] = parent_id;
        subscribe(topic_for_group(group));
    }
    else {
        log(fmt("[cluster/main] Got unexpected group_join_confirm for group '%s' which I already joined", group));
    }

}

event DeepCluster::handover_request(group: string, node_ids: set[string]) {
    log(fmt("[cluster/main] DeepCluster::handover_request: %s (%d)", group, |node_ids|));

    local num_nodes = |node_ids|;
}

event DeepCluster::handover_confirm(group: string, node_ids: set[string]) {
    log(fmt("[cluster/main] DeepCluster::handover_confirm: %s (%d)", group, |node_ids|));
}

