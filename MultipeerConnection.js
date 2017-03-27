var React = require('react-native');
var {
  DeviceEventEmitter,
  NativeModules
} = React;
var EventEmitter = require('events').EventEmitter;
var RCTMultipeerConnectivity = NativeModules.MultipeerConnectivity;
var Peer = require('./Peer');

class MultipeerConnection extends EventEmitter {

  constructor() {
    super();
    this._peers = {};
    this._connectedPeers = {};
    var peerFound = DeviceEventEmitter.addListener(
      'RCTMultipeerConnectivityPeerFound',
      ((event) => {
        console.log('RCTMultipeerConnectivityPeerFound', event);
        var peer = new Peer(event.peer.id, event.peer.info);
        this._peers[peer.id] = peer;
        this.emit('peerFound', {
          peer
        });
      }).bind(this));

    var peerLost = DeviceEventEmitter.addListener(
      'RCTMultipeerConnectivityPeerLost',
      ((event) => {
        console.log('RCTMultipeerConnectivityPeerLost', event);
        var peer = this._peers[event.peer.id];
        peer && peer.emit('lost');
        peer && this.emit('peerLost', {
          peer: {
            id: peer.id
          }
        });
        delete this._peers[event.peer.id];
        delete this._connectedPeers[event.peer.id];
      }).bind(this));

    var peerConnected = DeviceEventEmitter.addListener(
      'RCTMultipeerConnectivityPeerConnected',
      ((event) => {
        console.log('RCTMultipeerConnectivityPeerConnected', event);
        if (this._peers[event.peer.id]) {
          this._peers[event.peer.id].emit('connected');
          this._connectedPeers[event.peer.id] = this._peers[event.peer.id];
          this.emit('peerConnected', event);
        } else {
          console.log('RCTMultipeerConnectivityPeerConnected', 'missing peer');
        }
      }).bind(this));

    var peerConnecting = DeviceEventEmitter.addListener(
      'RCTMultipeerConnectivityPeerConnecting',
      ((event) => {
        console.log('RCTMultipeerConnectivityPeerConnecting', event);
        if (this._peers[event.peer.id]) {
          this._peers[event.peer.id].emit('connecting');
          this.emit('peerConnecting', event);
        } else {
          console.log('RCTMultipeerConnectivityPeerConnecting', 'missing peer');
        }
      }).bind(this));

    var peerDisconnected = DeviceEventEmitter.addListener(
      'RCTMultipeerConnectivityPeerDisconnected',
      ((event) => {
        console.log('RCTMultipeerConnectivityPeerDisconnected', event);
        if (this._peers[event.peer.id]) {
          this._peers[event.peer.id].emit('disconnected');
          delete this._connectedPeers[event.peer.id];
          this.emit('peerDisconnected', event);
        } else {
          console.log('RCTMultipeerConnectivityPeerDisconnected', 'missing peer');
        }
      }).bind(this));

    var streamOpened = DeviceEventEmitter.addListener(
      'RCTMultipeerConnectivityStreamOpened',
      ((event) => {
        console.log('RCTMultipeerConnectivityStreamOpened', event);
        this.emit('streamOpened', event);
      }).bind(this));

    var invited = DeviceEventEmitter.addListener(
      'RCTMultipeerConnectivityInviteReceived',
      ((event) => {
        console.log('RCTMultipeerConnectivityInviteReceived', event);
        if (this._peers[event.peer.id]) {
          event.sender = this._peers[event.peer.id];
          this.emit('invite', event);
        } else {
          console.log('RCTMultipeerConnectivityInviteReceived', 'missing peer');
        }
      }).bind(this));

    var dataReceived = DeviceEventEmitter.addListener(
      'RCTMultipeerConnectivityDataReceived',
      ((event) => {
        console.log('RCTMultipeerConnectivityDataReceived', event);
        if (this._peers[event.peer.id]) {
          event.sender = this._peers[event.peer.id];
          this.emit('data', event);
        } else {
          console.log('RCTMultipeerConnectivityDataReceived', 'missing peer');
        }
      }).bind(this));
  }

  getAllPeers() {
    return this._peers;
  }

  getConnectedPeers() {
    return this._connectedPeers;
  }

  send(recipients, data, callback) {
    if (!callback) {
      callback = () => {};
    }

    var recipientIds = recipients.map((recipient) => {
      if (recipient instanceof Peer) {
        return recipient.id;
      }
      return recipient;
    });

    RCTMultipeerConnectivity.send(recipientIds, data, callback);
  }

  broadcast(data, callback) {
    if (!callback) {
      callback = () => {};
    }
    RCTMultipeerConnectivity.broadcast(data, callback);
  }

  invite(peerId, callback) {
    if (!callback) {
      callback = () => {};
    }
    RCTMultipeerConnectivity.invite(peerId, callback);
  }

  rsvp(inviteId, accept, callback) {
    if (!callback) {
      callback = () => {};
    }
    RCTMultipeerConnectivity.rsvp(inviteId, accept, callback);
  }

  advertise(channel, info) {
    RCTMultipeerConnectivity.advertise(channel, info);
  }

  browse(channel) {
    RCTMultipeerConnectivity.browse(channel);
  }

  endAdvertise() {
    RCTMultipeerConnectivity.endAdvertise();
  }

  endBrowse() {
    RCTMultipeerConnectivity.endBrowse();
  }

  //  createStreamForPeer(peerId, name, callback) {
  //    if (!callback) {
  //      callback = () => {};
  //    }
  //    RCTMultipeerConnectivity.createStreamForPeer(peerId, name, callback);
  //  }
}

module.exports = MultipeerConnection;
