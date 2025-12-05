let bruteForceStore = {};

function getAttempts(ip) {
  return bruteForceStore[ip] || 0;
}

function incrementAttempts(ip) {
  bruteForceStore[ip] = (bruteForceStore[ip] || 0) + 1;
}

function resetAttempts(ip) {
  bruteForceStore[ip] = 0;
}

function clearStore() {
  bruteForceStore = {};
}

module.exports = {
  getAttempts,
  incrementAttempts,
  resetAttempts,
  clearStore
};
