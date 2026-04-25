function requireAdmin(req, res, next) {
  if (!req.auth || req.auth.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }
  return next();
}

module.exports = { requireAdmin };
