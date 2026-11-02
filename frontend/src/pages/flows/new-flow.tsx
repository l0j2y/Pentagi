import { useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

import { AppHeader, AppHeaderContent, AppHeaderTitle } from '@/components/layouts/app/app-header';
import { Card, CardContent } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { FlowForm, type FlowFormValues } from '@/features/flows/flow-form';
import { VulnScanForm } from '@/features/flows/vuln-scan-form';
import { routes } from '@/lib/routes';
import { useFlows } from '@/providers/flows-provider';
import { useProviders } from '@/providers/providers-provider';
import { useSystemSettings } from '@/providers/system-settings-provider';

type FlowType = 'assistant' | 'automation' | 'vulnscan';

const VALID_FLOW_TYPES: FlowType[] = ['assistant', 'automation', 'vulnscan'];

function NewFlow() {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();

    const { selectedProvider } = useProviders();
    const { createFlow, createFlowWithAssistant } = useFlows();
    const { settings } = useSystemSettings();

    const initialTab = useMemo<FlowType>(() => {
        const tab = searchParams.get('tab');
        return tab && VALID_FLOW_TYPES.includes(tab as FlowType) ? (tab as FlowType) : 'automation';
    }, [searchParams]);

    const [isLoading, setIsLoading] = useState(false);
    const [flowType, setFlowType] = useState<FlowType>(initialTab);

    const shouldUseAgents = useMemo(() => {
        return settings?.assistantUseAgents ?? false;
    }, [settings?.assistantUseAgents]);

    const handleSubmit = async (values: FlowFormValues) => {
        if (isLoading) {
            return;
        }

        setIsLoading(true);

        try {
            // Vuln-scan always uses the automation flow type (the pentester
            // agent is invoked regardless of flow type when the task involves
            // security testing).
            const flowId = flowType === 'assistant' ? await createFlowWithAssistant(values) : await createFlow(values);

            if (flowId) {
                const tab = flowType === 'assistant' ? 'assistant' : 'automation';
                navigate(routes.flow(flowId, { tab }));
            }
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <>
            <AppHeader>
                <AppHeaderContent>
                    <AppHeaderTitle>新建流程</AppHeaderTitle>
                </AppHeaderContent>
            </AppHeader>
            <div className="flex min-h-[calc(100dvh-3rem)] items-center justify-center p-4">
                <Card className="w-full max-w-2xl">
                    <CardContent className="flex flex-col gap-4 pt-6">
                        <div className="flex flex-col gap-2 text-center">
                            <h2 className="text-2xl font-semibold">创建新流程</h2>
                            <p className="text-muted-foreground">描述你希望 PentAGI 测试的内容</p>
                        </div>
                        <Tabs
                            onValueChange={(value) => setFlowType(value as FlowType)}
                            value={flowType}
                        >
                            <TabsList className="grid w-full grid-cols-3">
                                <TabsTrigger
                                    disabled={isLoading}
                                    value="automation"
                                >
                                    自动化
                                </TabsTrigger>
                                <TabsTrigger
                                    disabled={isLoading}
                                    value="assistant"
                                >
                                    助手
                                </TabsTrigger>
                                <TabsTrigger
                                    disabled={isLoading}
                                    value="vulnscan"
                                >
                                    漏洞检测
                                </TabsTrigger>
                            </TabsList>

                            <TabsContent value="automation">
                                <FlowForm
                                    defaultValues={{
                                        providerName: selectedProvider?.name ?? '',
                                        useAgents: shouldUseAgents,
                                    }}
                                    isSubmitting={isLoading}
                                    onSubmit={handleSubmit}
                                    placeholder={
                                        !isLoading
                                            ? '描述你希望 PentAGI 测试的内容...'
                                            : '正在创建流程...'
                                    }
                                    type="automation"
                                />
                            </TabsContent>

                            <TabsContent value="assistant">
                                <FlowForm
                                    defaultValues={{
                                        providerName: selectedProvider?.name ?? '',
                                        useAgents: shouldUseAgents,
                                    }}
                                    isSubmitting={isLoading}
                                    onSubmit={handleSubmit}
                                    placeholder={
                                        !isLoading
                                            ? '你希望我帮你做什么？'
                                            : '正在创建流程...'
                                    }
                                    type="assistant"
                                />
                            </TabsContent>

                            <TabsContent value="vulnscan">
                                <VulnScanForm
                                    isSubmitting={isLoading}
                                    onSubmit={handleSubmit}
                                />
                            </TabsContent>
                        </Tabs>
                    </CardContent>
                </Card>
            </div>
        </>
    );
}

export default NewFlow;
