const config = require("./config");
const app = require("./app");

const PORT = config.PORT || 3000;

app.listen(PORT, () => {
  console.log(`DineDesk API server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
  // Never log secrets, passwords, or tokens
});
