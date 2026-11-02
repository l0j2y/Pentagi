import { Shield } from 'lucide-react';
import { z } from 'zod';

import { Button } from '@/components/ui/button';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Spinner } from '@/components/ui/spinner';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useAppForm } from '@/hooks/use-app-form';
import type { FlowFormValues } from '@/features/flows/flow-form';
import { getProviderDisplayName } from '@/models/provider';
import { useProviders } from '@/providers/providers-provider';

const VALID_SCANNERS = ['nuclei', 'nikto', 'sslscan'] as const;
const VALID_SEVERITIES = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;

// Use plain string types (no z.enum / z.coerce) so the form's input and
// output types stay identical — this avoids a Control generic mismatch with
// the shadcn Form component. Conversions happen in the submit handler.
const formSchema = z.object({
    target: z
        .string()
        .trim()
        .min(1, { message: '请输入扫描目标' })
        .refine(
            (v) =>
                v.startsWith('http://') ||
                v.startsWith('https://') ||
                /^[\w.-]+(\/\S*)?$/.test(v),
            { message: '目标应为 URL（http:// 或 https:// 开头）或主机名/IP' },
        ),
    scanner: z.string().refine((v) => VALID_SCANNERS.includes(v as (typeof VALID_SCANNERS)[number]), {
        message: '请选择扫描器',
    }),
    ports: z.string(),
    severity: z.string().refine((v) => VALID_SEVERITIES.includes(v as (typeof VALID_SEVERITIES)[number]), {
        message: '请选择严重性级别',
    }),
    rateLimit: z.string(),
    timeout: z.string(),
    detach: z.boolean(),
});

export type VulnScanFormValues = z.infer<typeof formSchema>;

export interface VulnScanFormProps {
    isSubmitting?: boolean;
    onSubmit: (values: FlowFormValues) => Promise<void> | void;
}

const scannerOptions: { value: string; label: string; desc: string }[] = [
    { value: 'nuclei', label: 'Nuclei', desc: '模板化漏洞扫描（推荐，覆盖 CVE/配置/信息泄露）' },
    { value: 'nikto', label: 'Nikto', desc: 'Web 服务器配置错误与已知漏洞检测' },
    { value: 'sslscan', label: 'SSLscan', desc: 'TLS/SSL 配置分析（POODLE/Heartbleed/弱密码套件）' },
];

const severityOptions: { value: string; label: string }[] = [
    { value: 'all', label: '全部级别' },
    { value: 'critical', label: '严重及以上' },
    { value: 'high', label: '高危及以上' },
    { value: 'medium', label: '中危及以上' },
    { value: 'low', label: '低危及以上' },
    { value: 'info', label: '仅信息' },
];

function buildScanMessage(values: VulnScanFormValues): string {
    const lines: string[] = [];

    lines.push(`请使用 vulnscan 工具对以下目标执行漏洞扫描：`);
    lines.push(``);
    lines.push(`- 目标（target）：${values.target}`);
    lines.push(`- 扫描器（scanner）：${values.scanner}`);

    if (values.ports && values.ports.trim()) {
        lines.push(`- 端口（ports）：${values.ports.trim()}`);
    }

    if (values.severity && values.severity !== 'all') {
        lines.push(`- 严重性过滤（severity）：${values.severity} 及以上`);
    }

    if (values.rateLimit && values.rateLimit.trim()) {
        const rl = parseInt(values.rateLimit, 10);
        if (!Number.isNaN(rl)) {
            lines.push(`- 速率限制（rate_limit）：${rl} req/s`);
        }
    }

    if (values.timeout && values.timeout.trim()) {
        const t = parseInt(values.timeout, 10);
        if (!Number.isNaN(t)) {
            lines.push(`- 超时（timeout）：${t} 秒`);
        }
    }

    if (values.detach) {
        lines.push(`- 后台执行（detach）：true`);
    }

    lines.push(``);
    lines.push(`要求：`);
    lines.push(`1. 直接调用 vulnscan 工具，不要用终端手动拼接扫描器命令`);
    lines.push(`2. 扫描完成后，对每条发现给出证据、CVE/CVSS、置信度和修复建议`);
    lines.push(`3. 如目标为本地地址（127.x/10.x/192.168.x/172.16-31.x），请先确认 VULNSCAN_ALLOW_LOCAL 已开启`);

    return lines.join('\n');
}

export function VulnScanForm({ isSubmitting = false, onSubmit }: VulnScanFormProps) {
    const { providers, selectedProvider, setSelectedProvider } = useProviders();

    const form = useAppForm({
        schema: formSchema,
        defaultValues: {
            target: '',
            scanner: 'nuclei',
            ports: '',
            severity: 'all',
            rateLimit: '50',
            timeout: '1800',
            detach: false,
        },
    });

    const { control, handleSubmit, watch } = form;

    const handleFormSubmit = (values: VulnScanFormValues) => {
        const flowValues: FlowFormValues = {
            message: buildScanMessage(values),
            providerName: selectedProvider?.name || providers[0]?.name || '',
            resourceIds: [],
            useAgents: false,
        };
        void onSubmit(flowValues);
    };

    const scanner = watch('scanner');
    const showPorts = scanner === 'nuclei' || scanner === 'nikto';

    return (
        <Form {...form}>
            <form
                className="flex flex-col gap-4"
                onSubmit={handleSubmit(handleFormSubmit)}
            >
                {/* Provider selector */}
                <div className="flex flex-col gap-1.5">
                    <label className="text-sm font-medium">模型 Provider</label>
                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                        {providers.map((p) => (
                            <button
                                key={p.name}
                                type="button"
                                onClick={() => setSelectedProvider(p)}
                                className={`rounded-md border px-3 py-2 text-left text-sm transition-colors ${
                                    selectedProvider?.name === p.name
                                        ? 'border-primary bg-primary/10'
                                        : 'border-border hover:bg-accent'
                                }`}
                            >
                                <span className="font-medium">{getProviderDisplayName(p)}</span>
                            </button>
                        ))}
                    </div>
                    {providers.length === 0 && (
                        <p className="text-sm text-destructive">未配置 Provider，请先在设置中添加模型</p>
                    )}
                </div>

                {/* Target */}
                <FormField
                    control={control}
                    name="target"
                    render={({ field }) => (
                        <FormItem>
                            <FormLabel>扫描目标</FormLabel>
                            <FormControl>
                                <Input
                                    placeholder="https://example.com 或 10.0.0.5"
                                    {...field}
                                    disabled={isSubmitting}
                                />
                            </FormControl>
                            <FormDescription>URL、主机名或 IP（可带端口）。本地地址需开启 VULNSCAN_ALLOW_LOCAL</FormDescription>
                            <FormMessage />
                        </FormItem>
                    )}
                />

                {/* Scanner selector */}
                <FormField
                    control={control}
                    name="scanner"
                    render={({ field }) => (
                        <FormItem>
                            <FormLabel>扫描器</FormLabel>
                            <Tabs
                                value={field.value}
                                onValueChange={(v) => field.onChange(v)}
                            >
                                <TabsList className="grid w-full grid-cols-3">
                                    {scannerOptions.map((opt) => (
                                        <TabsTrigger
                                            key={opt.value}
                                            value={opt.value}
                                            disabled={isSubmitting}
                                        >
                                            {opt.label}
                                        </TabsTrigger>
                                    ))}
                                </TabsList>
                                {scannerOptions.map((opt) => (
                                    <TabsContent
                                        key={opt.value}
                                        value={opt.value}
                                        className="text-sm text-muted-foreground"
                                    >
                                        {opt.desc}
                                    </TabsContent>
                                ))}
                            </Tabs>
                            <FormMessage />
                        </FormItem>
                    )}
                />

                {/* Ports (nuclei/nikto only) */}
                {showPorts && (
                    <FormField
                        control={control}
                        name="ports"
                        render={({ field }) => (
                            <FormItem>
                                <FormLabel>端口（可选）</FormLabel>
                                <FormControl>
                                    <Input
                                        placeholder="80,443 或 1-1000"
                                        {...field}
                                        value={field.value ?? ''}
                                        disabled={isSubmitting}
                                    />
                                </FormControl>
                                <FormDescription>逗号分隔的端口或范围，留空使用默认端口</FormDescription>
                                <FormMessage />
                            </FormItem>
                        )}
                    />
                )}

                {/* Severity filter */}
                <FormField
                    control={control}
                    name="severity"
                    render={({ field }) => (
                        <FormItem>
                            <FormLabel>严重性过滤</FormLabel>
                            <Select
                                onValueChange={field.onChange}
                                value={field.value}
                                disabled={isSubmitting}
                            >
                                <FormControl>
                                    <SelectTrigger>
                                        <SelectValue placeholder="选择严重性级别" />
                                    </SelectTrigger>
                                </FormControl>
                                <SelectContent>
                                    {severityOptions.map((opt) => (
                                        <SelectItem
                                            key={opt.value}
                                            value={opt.value}
                                        >
                                            {opt.label}
                                        </SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                            <FormMessage />
                        </FormItem>
                    )}
                />

                {/* Rate limit + Timeout */}
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <FormField
                        control={control}
                        name="rateLimit"
                        render={({ field }) => (
                            <FormItem>
                                <FormLabel>速率限制 (req/s)</FormLabel>
                                <FormControl>
                                    <Input
                                        type="number"
                                        min={1}
                                        max={100}
                                        placeholder="50"
                                        {...field}
                                        value={field.value ?? ''}
                                        disabled={isSubmitting}
                                    />
                                </FormControl>
                                <FormDescription>1-100，默认 50，硬上限 100</FormDescription>
                                <FormMessage />
                            </FormItem>
                        )}
                    />

                    <FormField
                        control={control}
                        name="timeout"
                        render={({ field }) => (
                            <FormItem>
                                <FormLabel>超时（秒）</FormLabel>
                                <FormControl>
                                    <Input
                                        type="number"
                                        min={1}
                                        max={10800}
                                        placeholder="1800"
                                        {...field}
                                        value={field.value ?? ''}
                                        disabled={isSubmitting}
                                    />
                                </FormControl>
                                <FormDescription>1-10800，默认 1800（30 分钟）</FormDescription>
                                <FormMessage />
                            </FormItem>
                        )}
                    />
                </div>

                {/* Detach toggle */}
                <FormField
                    control={control}
                    name="detach"
                    render={({ field }) => (
                        <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3">
                            <div className="space-y-0.5">
                                <FormLabel>后台执行</FormLabel>
                                <FormDescription>
                                    扫描在后台运行，立即返回；稍后用文件工具读取 /opt/assessment/findings/ 下的结果
                                </FormDescription>
                            </div>
                            <FormControl>
                                <Switch
                                    checked={field.value}
                                    onCheckedChange={field.onChange}
                                    disabled={isSubmitting}
                                />
                            </FormControl>
                        </FormItem>
                    )}
                />

                {/* Submit */}
                <Button
                    className="w-full"
                    disabled={isSubmitting || providers.length === 0}
                    type="submit"
                >
                    {isSubmitting ? (
                        <>
                            <Spinner className="mr-2 size-4" />
                            正在创建扫描任务...
                        </>
                    ) : (
                        <>
                            <Shield className="mr-2 size-4" />
                            开始漏洞扫描
                        </>
                    )}
                </Button>

                <p className="text-center text-xs text-muted-foreground">
                    扫描仅做非破坏性检测，不利用、不爆破、不修改目标数据
                </p>
            </form>
        </Form>
    );
}
