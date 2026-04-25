const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');

function issueRecoveryJwt({ recoveryId, userId }) {
  const expirySeconds = Number(process.env.RECOVERY_TOKEN_EXPIRY_SECONDS || 300);
  const jti = uuidv4();

  const token = jwt.sign(
    {
      recoveryId,
      userId,
      jti,
      kind: 'recovery'
    },
    process.env.BACKUP_NODE_SECRET,
    { expiresIn: expirySeconds }
  );

  const decoded = jwt.decode(token);
  return {
    token,
    jti,
    expiresAt: new Date(decoded.exp * 1000)
  };
}

module.exports = {
  issueRecoveryJwt
};
