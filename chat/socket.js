const { addMessage, getMessages } = require("./store");
const { maskChatId } = require("./utils");
const crypto = require("crypto");


function setupSocket(io) {
  io.on("connection", (socket) => {
    const { chatId } = socket.handshake.auth;

    if (!chatId) {
      socket.disconnect();
      return;
    }

    const maskedChatId = maskChatId(chatId);
    socket.chatId = chatId;
    socket.maskedChatId = maskedChatId;

    socket.join("GLOBAL");

    socket.emit("chat:init", {
      chatId,
      maskedChatId,
    });

    socket.emit("chat:history", getMessages());

    socket.on("chat:send", ({text,gender , replyTo}) => {
      if (typeof text !== "string" || !text.trim() || text.length > 1000) return;
      const msg = {
    msgId: crypto.randomUUID(),
    senderChatId: socket.chatId,
    maskedChatId: socket.maskedChatId,
    text: text.trim(),
    gender,
    timestamp: Date.now(),
    replyTo: replyTo || null,
  };

      addMessage(msg);
      io.to("GLOBAL").emit("chat:message", msg);
    });
  });
}

module.exports = setupSocket;

