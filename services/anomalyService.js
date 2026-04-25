const { v4: uuidv4 } = require('uuid');
const Incident = require('../models/Incident');
const sessionRegistry = require('./sessionRegistry');
const { enforceIncident } = require('./enforcementService');

async function recordAnomaly(context = {}) {
  const incident = await Incident.create({
    incidentId: `INC-${uuidv4().slice(0, 10)}`,
    type: context.type || 'UNKNOWN_ANOMALY',
    severity: context.severity || 'medium',
    reason: context.reason || 'Security anomaly detected',
    userId: context.userId || null,
    username: context.username || null,
    roomId: context.roomId || null,
    nodeId: context.nodeId || null,
    socketId: context.socketId || null,
    sourceIp: context.sourceIp || null,
    sourceGeo: context.sourceGeo || null,
    userAgent: context.userAgent || null,
    origin: context.origin || null,
    actionTaken: 'pending',
    status: 'open',
    createdAt: new Date(),
    metadata: context.metadata || {}
  });

  const actionTaken = await enforceIncident(incident);
  incident.actionTaken = actionTaken;
  await incident.save();

  const adminEvent = {
    type: 'INCIDENT_CREATED',
    incidentId: incident.incidentId,
    severity: incident.severity,
    anomalyType: incident.type,
    reason: incident.reason,
    userId: incident.userId,
    username: incident.username,
    roomId: incident.roomId,
    nodeId: incident.nodeId,
    actionTaken
  };

  sessionRegistry.broadcastToAdmins(adminEvent);
  sessionRegistry.broadcastToAdmins({
    type: 'ADMIN_SECURITY_ALERT',
    incidentId: incident.incidentId,
    severity: incident.severity,
    reason: incident.reason,
    actionTaken
  });

  if (incident.roomId) {
    sessionRegistry.broadcastToRoom(String(incident.roomId), {
      type: 'SECURITY_ACTION_TAKEN',
      incidentId: incident.incidentId,
      roomId: incident.roomId,
      reason: incident.reason,
      actionTaken
    });
  }

  return incident;
}

module.exports = {
  recordAnomaly
};
