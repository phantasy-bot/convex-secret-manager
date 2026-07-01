import { cronJobs } from "convex/server";
import { internal } from "./_generated/api.js";

const crons = cronJobs();

crons.interval(
  "sweep expired issued keys",
  { hours: 1 },
  (internal as any).issuedSweep.sweepExpired,
  {},
);
crons.interval(
  "sweep idle issued keys",
  { hours: 1 },
  (internal as any).issuedSweep.sweepIdleExpired,
  {},
);

export default crons;