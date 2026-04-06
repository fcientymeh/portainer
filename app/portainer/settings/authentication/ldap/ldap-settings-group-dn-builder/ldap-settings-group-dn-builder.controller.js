export default class LdapSettingsGroupDnBuilderController {
  /* @ngInject */
  constructor($scope) {
    this.$scope = $scope;
    this.groupName = '';
    this.entries = '';

    this.onEntriesChange = this.onEntriesChange.bind(this);
    this.onGroupNameChange = this.onGroupNameChange.bind(this);
    this.onGroupChange = this.onGroupChange.bind(this);
  }

  onEntriesChange(entries) {
    this.$scope.$evalAsync(() => {
      this.onGroupChange(this.groupName, entries);
    });
  }

  onGroupNameChange() {
    this.onGroupChange(this.groupName, this.entries);
  }

  onGroupChange(groupName, entries) {
    if (!groupName) {
      return;
    }
    const groupNameEntry = `cn=${groupName}`;
    this.onChange(this.index, entries || this.suffix ? `${groupNameEntry},${entries || this.suffix}` : groupNameEntry);
  }

  parseEntries(value, suffix) {
    if (value === suffix) {
      this.groupName = '';
      this.entries = suffix;
      return;
    }

    const [groupName, entries] = this.ngModel.split(/,(.+)/);
    this.groupName = groupName.replace('cn=', '');
    this.entries = entries || '';
  }

  $onChange({ ngModel, suffix }) {
    if ((!suffix || suffix.isFirstChange()) && !ngModel) {
      return;
    }
    this.parseEntries(ngModel.value, suffix.value);
  }

  $onInit() {
    this.parseEntries(this.ngModel, this.suffix);
  }
}
