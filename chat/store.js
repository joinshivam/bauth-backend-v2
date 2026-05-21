const messages = [];
const blockedChatIds = new Set();

function saveMessage(msg) {
  messages.push(msg);
}
function addMessage(msg) {
  messages.push(msg);
  if (messages.length > 100) messages.shift();
}

function getMessages(limit = 100) {
  return messages.slice(-limit);
}

function blockChatId(chatId) {
  blockedChatIds.add(chatId);
}

function isBlocked(chatId) {
  return blockedChatIds.has(chatId);
}

module.exports = {
  saveMessage,
  getMessages,
  blockChatId,
  isBlocked,
  addMessage
};
