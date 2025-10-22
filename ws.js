// 1️⃣ Create connection
const ws = new WebSocket("ws://localhost:9969");

// 2️⃣ When connected, send a JSON command
ws.onopen = () => {
    console.log("✅ Connected to WebSocket!");

    // build request object
    const request = {
        command: "get_devices",
        host_api: "Windows WDM-KS"   // optional; can be empty or "ALSA"/"ASIO"/etc
    };

    // send as JSON string
    ws.send(JSON.stringify(request));
    console.log("📤 Sent:", request);
};

// 3️⃣ Handle server response
ws.onmessage = event => {
    try {
        const response = JSON.parse(event.data);
        console.log("📨 Received:", response);
    } catch (err) {
        console.error("❌ JSON parse error:", err);
        console.log("Raw message:", event.data);
    }
};

// 4️⃣ Handle errors and close
ws.onerror = err => console.error("❌ WebSocket error:", err);
ws.onclose = () => console.log("🔌 Disconnected");

() => console.log("🔌 Disconnected")

// Example: Request device list
// ws.send(JSON.stringify({ command: "get_devices" }));