import { useState } from 'react';
import { Alert, Button, Input, Space, Switch, Typography } from 'antd';
import { CloudDownloadOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import type { AllSetting } from '@/models/setting';
import { SettingListItem } from '@/components/ui';
import { HttpUtil } from '@/utils';

interface InboundSyncTabProps {
  allSetting: AllSetting;
  updateSetting: (patch: Partial<AllSetting>) => void;
}

interface SyncResult {
  Added: number;
  Removed: number;
  Skipped: string[] | null;
}

/* Mirrors a remote share-link subscription into local inbounds. The three
   settings below feed the 30-minute job; the button runs the same refresh
   immediately so an operator can see the result before waiting. */
export default function InboundSyncTab({ allSetting, updateSetting }: InboundSyncTabProps) {
  const { t } = useTranslation();
  const [syncing, setSyncing] = useState(false);
  const [lastResult, setLastResult] = useState<SyncResult | null>(null);

  async function runSync() {
    setSyncing(true);
    try {
      // HttpUtil already surfaces the server's error toast for a failed call.
      const res = await HttpUtil.post<SyncResult>('/panel/api/inbounds/syncSubscription');
      if (res.obj) {
        setLastResult(res.obj);
      }
    } finally {
      setSyncing(false);
    }
  }

  return (
    <>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message={t('pages.settings.inboundSync.hint')}
      />

      <SettingListItem
        paddings="small"
        title={t('pages.settings.inboundSync.enable')}
        description={t('pages.settings.inboundSync.enableDesc')}
      >
        <Switch
          checked={allSetting.subInboundSyncEnable}
          onChange={(v) => updateSetting({ subInboundSyncEnable: v })}
        />
      </SettingListItem>

      <SettingListItem
        paddings="small"
        title={t('pages.settings.inboundSync.url')}
        description={t('pages.settings.inboundSync.urlDesc')}
      >
        <Input
          value={allSetting.subInboundSyncUrl}
          placeholder="https://example.com/subscription.txt"
          onChange={(e) => updateSetting({ subInboundSyncUrl: e.target.value })}
        />
      </SettingListItem>

      <SettingListItem
        paddings="small"
        title={t('pages.settings.inboundSync.domain')}
        description={t('pages.settings.inboundSync.domainDesc')}
      >
        <Input
          value={allSetting.subInboundSyncDomain}
          placeholder="panel.example.com"
          onChange={(e) => updateSetting({ subInboundSyncDomain: e.target.value })}
        />
      </SettingListItem>

      <SettingListItem
        paddings="small"
        title={t('pages.settings.inboundSync.cfDomain')}
        description={t('pages.settings.inboundSync.cfDomainDesc')}
      >
        <Input
          value={allSetting.subInboundSyncCfDomain}
          placeholder="aipanl.example.com"
          onChange={(e) => updateSetting({ subInboundSyncCfDomain: e.target.value })}
        />
      </SettingListItem>

      <SettingListItem
        paddings="small"
        title={t('pages.settings.inboundSync.run')}
        description={t('pages.settings.inboundSync.runDesc')}
      >
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button
            icon={<CloudDownloadOutlined />}
            loading={syncing}
            onClick={runSync}
            disabled={!allSetting.subInboundSyncUrl}
          >
            {t('pages.settings.inboundSync.run')}
          </Button>
          {lastResult && (
            <Typography.Text type="secondary">
              {t('pages.settings.inboundSync.runResult', {
                added: lastResult.Added,
                removed: lastResult.Removed,
                skipped: lastResult.Skipped?.length ?? 0,
              })}
            </Typography.Text>
          )}
        </Space>
      </SettingListItem>
    </>
  );
}
