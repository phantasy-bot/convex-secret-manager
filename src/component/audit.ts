export async function writeAuditEvent(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ctx: { db: any },
  args: {
    ownerId: string;
    namespace: string;
    action: string;
    targetName: string;
    actorId?: string;
    metadata?: unknown;
  },
): Promise<void> {
  await ctx.db.insert("auditEvents", {
    ownerId: args.ownerId,
    namespace: args.namespace,
    action: args.action,
    targetName: args.targetName,
    actorId: args.actorId,
    metadata: args.metadata,
    createdAt: Date.now(),
  });
}