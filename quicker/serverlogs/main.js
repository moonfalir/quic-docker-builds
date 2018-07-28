"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const server_1 = require("./quicker/server");
const fs_1 = require("fs");
const http_helper_1 = require("./http/http0.9/http.helper");
const quicker_event_1 = require("./quicker/quicker.event");
let host = process.argv[2] || "127.0.0.1";
let port = process.argv[3] || 4433;
let key = process.argv[4] || "../keys/selfsigned_default.key";
let cert = process.argv[5] || "../keys/selfsigned_default.crt";
if (isNaN(Number(port))) {
    console.log("port must be a number: node ./main.js 127.0.0.1 4433 ca.key ca.cert");
    process.exit(-1);
}
console.log("Running QUICker server at " + host + ":" + port + ", with certs: " + key + ", " + cert);
var httpHelper = new http_helper_1.HttpHelper();
var server = server_1.Server.createServer({
    key: fs_1.readFileSync(key),
    cert: fs_1.readFileSync(cert)
});
server.listen(Number(port), host);
server.on(quicker_event_1.QuickerEvent.NEW_STREAM, (quicStream) => {
    var bufferedData = Buffer.alloc(0);
    quicStream.on(quicker_event_1.QuickerEvent.STREAM_DATA_AVAILABLE, (data) => {
        bufferedData = Buffer.concat([bufferedData, data]);
    });
    quicStream.on(quicker_event_1.QuickerEvent.STREAM_END, () => {
        var output = httpHelper.handleRequest(bufferedData);
        quicStream.end(output);
    });
});
server.on(quicker_event_1.QuickerEvent.ERROR, (error) => {
    console.log(error.message);
});
server.on(quicker_event_1.QuickerEvent.CONNECTION_DRAINING, (connectionId) => {
    console.log("connection with connectionID " + connectionId + " is draining");
});
server.on(quicker_event_1.QuickerEvent.CONNECTION_CLOSE, (connectionId) => {
    console.log("connection with connectionID " + connectionId + " is closed");
});
