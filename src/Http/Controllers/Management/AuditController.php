<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Audit\ListAuthAuditsAction;
use Nvl\Auth\Actions\Audit\ShowAuthAuditAction;
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;
use Nvl\Auth\Models\AuthAudit;

/**
 * Handles authorized simple Auth audit listing transport.
 */
final class AuditController extends AuthenticatedController
{
    /**
     * List Auth audits.
     */
    public function index(Request $request, ListAuthAuditsAction $action): JsonResponse
    {
        $page = $action->execute($this->subject($request), (int) $request->integer('per_page', 50));

        return response()->json(['data' => $page, 'code' => 'auth_audits_listed', 'message' => 'Auth audits were listed.']);
    }

    /**
     * Show one Auth audit with its authorized context payload.
     */
    public function show(
        Request $request,
        AuthAudit $authAudit,
        ShowAuthAuditAction $action,
    ): JsonResponse {
        $audit = $action->execute($this->subject($request), $authAudit);

        return response()->json([
            'data' => [
                'id' => $audit->identifier(),
                'action' => $audit->action,
                'outcome' => $audit->outcome,
                'subject' => $audit->subject_type === null ? null : ['type' => $audit->subject_type, 'id' => $audit->subject_id],
                'actor' => $audit->actor_type === null ? null : ['type' => $audit->actor_type, 'id' => $audit->actor_id],
                'client_id' => $audit->client_id,
                'request_id' => $audit->request_id,
                'ip_address' => $audit->ip_address,
                'user_agent' => $audit->user_agent,
                'metadata' => $audit->metadata,
                'created_at' => $audit->created_at?->toIso8601String(),
            ],
            'code' => 'auth_audit_shown',
            'message' => 'The Auth audit was shown.',
        ]);
    }
}
