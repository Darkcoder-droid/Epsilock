const express = require('express');
const { requireAuth, requireRole } = require('../../shared/auth');

const router = express.Router();

router.use(requireAuth, requireRole('user'));

router.get('/', async (req, res) => {
  const phase1 = req.app.locals.phase1;
  if (req.auth.assignedNodeType !== phase1.nodeType) {
    return res.status(403).send('Forbidden for this node type');
  }

  const rooms = await phase1.getUserRooms(req.auth.sub);

  return res.render('dashboard', {
    auth: req.auth,
    nodeType: phase1.nodeType,
    nodeId: phase1.nodeId,
    rooms
  });
});

router.get('/chat/:roomId', async (req, res) => {
  const phase1 = req.app.locals.phase1;
  const rooms = await phase1.getUserRooms(req.auth.sub);
  const room = rooms.find((r) => r.roomId === req.params.roomId);

  if (!room) {
    return res.status(404).send('Room not available for this user');
  }

  return res.render('chat', {
    auth: req.auth,
    nodeType: phase1.nodeType,
    nodeId: phase1.nodeId,
    room
  });
});

module.exports = router;
