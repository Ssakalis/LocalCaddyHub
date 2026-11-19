// Enough for roughly 1,500 fully expanded handlers; admission also checks the GET representation.
const CONFIG_JSON_LIMIT = 2 * 1024 * 1024;

module.exports = { CONFIG_JSON_LIMIT };
